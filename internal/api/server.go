package api

import (
	"net/http"
	"time"

	"github.com/etherance/lockr/internal/audit"
	"github.com/etherance/lockr/internal/auth"
	"github.com/etherance/lockr/internal/config"
	"github.com/etherance/lockr/internal/policy"
	"github.com/etherance/lockr/internal/secrets"
)

type Config struct {
	Cfg          *config.Config
	DevMode      bool
	Sessions     *auth.SessionStore
	Ed25519Auth  *auth.Ed25519Auth
	TOTPAuth     *auth.TOTPAuth
	AdminAuth    *auth.AdminAuth
	UserAuth     *auth.UserAuth
	KVStore      *secrets.KVStore
	DBStore      *secrets.DBStore
	TransitStore *secrets.TransitStore
	Policy       *policy.Engine
	AuditLog     *audit.Logger
}

type Server struct {
	cfg          *config.Config
	devMode      bool
	sessions     *auth.SessionStore
	ed25519Auth  *auth.Ed25519Auth
	totpAuth     *auth.TOTPAuth
	adminAuth    *auth.AdminAuth
	userAuth     *auth.UserAuth
	kvStore      *secrets.KVStore
	dbStore      *secrets.DBStore
	transitStore *secrets.TransitStore
	policy       *policy.Engine
	auditLog     *audit.Logger
	startTime    time.Time
}

func New(cfg Config) *Server {
	return &Server{
		cfg:          cfg.Cfg,
		devMode:      cfg.DevMode,
		sessions:     cfg.Sessions,
		ed25519Auth:  cfg.Ed25519Auth,
		totpAuth:     cfg.TOTPAuth,
		adminAuth:    cfg.AdminAuth,
		userAuth:     cfg.UserAuth,
		kvStore:      cfg.KVStore,
		dbStore:      cfg.DBStore,
		transitStore: cfg.TransitStore,
		policy:       cfg.Policy,
		auditLog:     cfg.AuditLog,
		startTime:    time.Now(),
	}
}

func (s *Server) Handler() http.Handler {
	return s.routes()
}

func (s *Server) logAuthAttempt(r *http.Request, identity, method, status string) {
	if s.auditLog == nil {
		return
	}
	rid, _ := r.Context().Value(ctxRequestID).(string)
	start, _ := r.Context().Value(ctxStartTime).(time.Time)
	_ = s.auditLog.Log(audit.Entry{
		Timestamp:  time.Now().UTC(),
		Identity:   identity,
		AuthMethod: method,
		Operation:  r.Method,
		Path:       r.URL.Path,
		SourceIP:   r.RemoteAddr,
		RequestID:  rid,
		Status:     status,
		DurationMS: time.Since(start).Milliseconds(),
	})
}
