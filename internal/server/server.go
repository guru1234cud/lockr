package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/etherance/lockr/internal/api"
	"github.com/etherance/lockr/internal/audit"
	"github.com/etherance/lockr/internal/auth"
	"github.com/etherance/lockr/internal/config"
	"github.com/etherance/lockr/internal/policy"
	"github.com/etherance/lockr/internal/secrets"
	"github.com/etherance/lockr/internal/storage"
)

type Server struct {
	cfg *config.Config
	db  *storage.DB
	srv *http.Server
}

func New(cfg *config.Config) *Server {
	return &Server{cfg: cfg}
}

func (s *Server) Run(devMode bool) error {
	// Storage.
	dbOpts := storage.Options{
		DataDir:  s.cfg.Storage.DataDir,
		InMemory: devMode,
	}
	db, err := storage.Open(dbOpts)
	if err != nil {
		return fmt.Errorf("open storage: %w", err)
	}
	s.db = db
	defer db.Close()

	// Crypto.
	var crypto *storage.Crypto
	if devMode {
		// Generate ephemeral master key for dev mode.
		key, err := storage.GenerateMasterKey()
		if err != nil {
			return err
		}
		crypto = storage.NewCrypto(key)
	} else {
		passphrase := []byte(os.Getenv("LOCKR_PASSPHRASE"))
		if len(passphrase) == 0 {
			return fmt.Errorf("LOCKR_PASSPHRASE environment variable is required")
		}
		masterKey, err := storage.LoadMasterKey(s.cfg.Storage.MasterKeyPath, passphrase)
		if err != nil {
			return fmt.Errorf("load master key: %w", err)
		}
		defer storage.ZeroBytes(masterKey)
		crypto = storage.NewCrypto(masterKey)
	}

	// Audit logger.
	var auditLogger *audit.Logger
	if !devMode {
		auditLogger, err = audit.NewLogger(db, s.cfg.Audit.LogFile)
		if err != nil {
			return fmt.Errorf("init audit logger: %w", err)
		}
		defer auditLogger.Close()
	}

	// Policy engine.
	policyEngine := policy.NewEngine(s.cfg.Policy.Dir)
	if !devMode {
		if err := policyEngine.LoadAll(); err != nil {
			return fmt.Errorf("load policies: %w", err)
		}
	}

	// Auth subsystems.
	sessions := auth.NewSessionStore(db, s.cfg.Session.TTL)
	ed25519Auth := auth.NewEd25519Auth(db)
	totpAuth := auth.NewTOTPAuth(db)
	adminAuth := auth.NewAdminAuth(db)

	// Secret stores.
	kvStore := secrets.NewKVStore(db, crypto)
	dbStore := secrets.NewDBStore(db, crypto)
	transitStore := secrets.NewTransitStore(db, crypto)

	// HTTP API.
	apiServer := api.New(api.Config{
		Cfg:          s.cfg,
		DevMode:      devMode,
		Sessions:     sessions,
		Ed25519Auth:  ed25519Auth,
		TOTPAuth:     totpAuth,
		AdminAuth:    adminAuth,
		KVStore:      kvStore,
		DBStore:      dbStore,
		TransitStore: transitStore,
		Policy:       policyEngine,
		AuditLog:     auditLogger,
	})

	// DB janitor goroutine.
	if !devMode {
		go func() {
			interval := s.cfg.DynamicSecrets.CredentialJanitorInterval
			if interval == 0 {
				interval = 5 * time.Minute
			}
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for range ticker.C {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				_ = dbStore.RunJanitor(ctx)
				cancel()
			}
		}()
	}

	// TLS config.
	var tlsCfg *tls.Config
	if !devMode {
		cert, err := tls.LoadX509KeyPair(s.cfg.Server.TLSCert, s.cfg.Server.TLSKey)
		if err != nil {
			return fmt.Errorf("load TLS cert: %w", err)
		}
		tlsCfg = &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
		}
	}

	s.srv = &http.Server{
		Addr:      s.cfg.Server.Addr,
		Handler:   apiServer.Handler(),
		TLSConfig: tlsCfg,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// SIGHUP → reload policies.
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGHUP)
		for range c {
			fmt.Println("reloading policies...")
			_ = policyEngine.LoadAll()
		}
	}()

	// Graceful shutdown on SIGTERM/SIGINT.
	errCh := make(chan error, 1)
	go func() {
		if devMode {
			fmt.Println()
			fmt.Println("╔══════════════════════════════════════════════╗")
			fmt.Println("║   [DEV MODE — NOT FOR PRODUCTION]            ║")
			fmt.Println("║   No TLS, No Auth, In-Memory Storage         ║")
			fmt.Println("╚══════════════════════════════════════════════╝")
			fmt.Printf("\nListening on http://%s\n\n", s.cfg.Server.Addr)
			errCh <- s.srv.ListenAndServe()
		} else {
			fmt.Printf("Lockr listening on https://%s\n", s.cfg.Server.Addr)
			errCh <- s.srv.ListenAndServeTLS("", "")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	select {
	case err := <-errCh:
		return err
	case <-quit:
		fmt.Println("shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.srv.Shutdown(ctx)
	}
}
