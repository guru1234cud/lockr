package secrets

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/etherance/lockr/internal/storage"
	"github.com/oklog/ulid/v2"

	// Postgres driver — imported for side effects.
	_ "github.com/lib/pq"

	"database/sql"
)

type DBConfig struct {
	Name              string `json:"name"`
	Host              string `json:"host"`
	Port              int    `json:"port"`
	DBName            string `json:"dbname"`
	AdminUser         string `json:"admin_user"`
	AdminPassword     string `json:"admin_password"` // stored encrypted
	DefaultTTLStr     string `json:"default_ttl"`    // human-readable e.g. "1h", "30m"
	MaxTTLStr         string `json:"max_ttl"`        // human-readable e.g. "24h"
	CreationStatement string `json:"creation_statement"`
}

func (c *DBConfig) defaultTTL() time.Duration {
	if c.DefaultTTLStr == "" {
		return time.Hour
	}
	d, err := time.ParseDuration(c.DefaultTTLStr)
	if err != nil {
		return time.Hour
	}
	return d
}

func (c *DBConfig) maxTTL() time.Duration {
	if c.MaxTTLStr == "" {
		return 24 * time.Hour
	}
	d, err := time.ParseDuration(c.MaxTTLStr)
	if err != nil {
		return 24 * time.Hour
	}
	return d
}

type DBLease struct {
	LeaseID   string    `json:"lease_id"`
	RoleName  string    `json:"role_name"`
	DBConfig  string    `json:"db_config"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	ExpiresAt time.Time `json:"expires_at"`
}

type DBStore struct {
	db     *storage.DB
	crypto *storage.Crypto
}

func NewDBStore(db *storage.DB, crypto *storage.Crypto) *DBStore {
	return &DBStore{db: db, crypto: crypto}
}

// SetConfig writes or updates a DB dynamic credential configuration.
func (s *DBStore) SetConfig(cfg *DBConfig) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	enc, err := s.crypto.Encrypt("secrets/db/"+cfg.Name, data)
	if err != nil {
		return err
	}
	return s.db.Set("secrets/db/"+cfg.Name, enc)
}

// GetConfig retrieves a DB config by name (omits admin password from returned struct).
func (s *DBStore) GetConfig(name string) (*DBConfig, error) {
	return s.loadConfig(name)
}

// GetConfigSafe returns the config with admin password redacted.
func (s *DBStore) GetConfigSafe(name string) (*DBConfig, error) {
	cfg, err := s.loadConfig(name)
	if err != nil {
		return nil, err
	}
	cfg.AdminPassword = "[redacted]"
	return cfg, nil
}

// GenerateCreds creates a dynamic Postgres user and stores a lease.
func (s *DBStore) GenerateCreds(ctx context.Context, configName string) (*DBLease, error) {
	cfg, err := s.loadConfig(configName)
	if err != nil {
		return nil, err
	}

	connStr := fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=require",
		cfg.Host, cfg.Port, cfg.DBName, cfg.AdminUser, cfg.AdminPassword)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("open db connection: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	username := "lockr_" + randomHex(8)
	password := randomHex(16)

	// username is always "lockr_" + hex — safe to interpolate in identifier position.
	// Password uses $1 parameter to avoid any injection risk.
	var execErr error
	if cfg.CreationStatement == "" {
		_, execErr = db.ExecContext(ctx,
			fmt.Sprintf("CREATE USER %s WITH PASSWORD $1", username), password)
		if execErr == nil {
			_, execErr = db.ExecContext(ctx,
				fmt.Sprintf("GRANT CONNECT ON DATABASE %s TO %s", cfg.DBName, username))
		}
	} else {
		stmt := replaceAll(cfg.CreationStatement, "{{username}}", username)
		stmt = replaceAll(stmt, "{{password}}", password)
		_, execErr = db.ExecContext(ctx, stmt)
	}
	if execErr != nil {
		return nil, fmt.Errorf("create postgres user: %w", execErr)
	}

	ttl := cfg.defaultTTL()
	if ttl > cfg.maxTTL() {
		ttl = cfg.maxTTL()
	}

	lease := &DBLease{
		LeaseID:   ulid.MustNew(ulid.Now(), rand.Reader).String(),
		RoleName:  configName,
		DBConfig:  configName,
		Username:  username,
		Password:  password,
		ExpiresAt: time.Now().UTC().Add(ttl),
	}

	data, err := json.Marshal(lease)
	if err != nil {
		return nil, err
	}
	leaseKey := "secrets/db/leases/" + lease.LeaseID
	enc, err := s.crypto.Encrypt(leaseKey, data)
	if err != nil {
		return nil, err
	}
	if err := s.db.SetWithTTL(leaseKey, enc, ttl+time.Minute); err != nil {
		return nil, err
	}
	return lease, nil
}

// TestConnection verifies that the stored admin credentials can reach the database.
func (s *DBStore) TestConnection(ctx context.Context, configName string) error {
	cfg, err := s.loadConfig(configName)
	if err != nil {
		return err
	}
	connStr := fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=require",
		cfg.Host, cfg.Port, cfg.DBName, cfg.AdminUser, cfg.AdminPassword)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.PingContext(ctx)
}

// ListLeases returns all active leases for a given DB config name.
func (s *DBStore) ListLeases(configName string) ([]*DBLease, error) {
	all, err := s.db.Scan("secrets/db/leases/")
	if err != nil {
		return nil, err
	}
	var result []*DBLease
	now := time.Now().UTC()
	for key, data := range all {
		plain, err := s.crypto.Decrypt(key, data)
		if err != nil {
			continue
		}
		var lease DBLease
		if err := json.Unmarshal(plain, &lease); err != nil {
			continue
		}
		if lease.DBConfig != configName {
			continue
		}
		if now.Before(lease.ExpiresAt) {
			lease.Password = "[redacted]" // never expose password in listing
			result = append(result, &lease)
		}
	}
	return result, nil
}

// RevokeLease drops the Postgres user and removes the lease.
func (s *DBStore) RevokeLease(ctx context.Context, leaseID string) error {
	leaseKey := "secrets/db/leases/" + leaseID
	data, err := s.db.Get(leaseKey)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("lease %q not found", leaseID)
		}
		return err
	}
	plain, err := s.crypto.Decrypt(leaseKey, data)
	if err != nil {
		return err
	}
	var lease DBLease
	if err := json.Unmarshal(plain, &lease); err != nil {
		return err
	}
	return s.dropUser(ctx, lease.DBConfig, lease.Username, leaseID)
}

// ReconcileOrphans connects to each configured DB and drops any lockr_ users
// that have no active lease. Call this once on server startup.
func (s *DBStore) ReconcileOrphans(ctx context.Context) error {
	configs, err := s.db.List("secrets/db/")
	if err != nil {
		return err
	}

	// Build set of active usernames from leases.
	activeUsers := make(map[string]bool)
	leases, _ := s.db.Scan("secrets/db/leases/")
	for key, data := range leases {
		plain, err := s.crypto.Decrypt(key, data)
		if err != nil {
			continue
		}
		var lease DBLease
		if err := json.Unmarshal(plain, &lease); err != nil {
			continue
		}
		if time.Now().UTC().Before(lease.ExpiresAt) {
			activeUsers[lease.Username] = true
		}
	}

	for _, cfgKey := range configs {
		// Skip lease keys.
		if len(cfgKey) > len("secrets/db/leases/") &&
			cfgKey[:len("secrets/db/leases/")] == "secrets/db/leases/" {
			continue
		}
		name := cfgKey[len("secrets/db/"):]
		cfg, err := s.loadConfig(name)
		if err != nil {
			continue
		}
		connStr := fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=require",
			cfg.Host, cfg.Port, cfg.DBName, cfg.AdminUser, cfg.AdminPassword)
		db, err := sql.Open("postgres", connStr)
		if err != nil {
			continue
		}
		rows, err := db.QueryContext(ctx,
			"SELECT usename FROM pg_catalog.pg_user WHERE usename LIKE 'lockr_%'")
		if err != nil {
			db.Close()
			continue
		}
		for rows.Next() {
			var uname string
			if err := rows.Scan(&uname); err != nil {
				continue
			}
			if !activeUsers[uname] {
				_, _ = db.ExecContext(ctx, fmt.Sprintf("DROP USER IF EXISTS %s", uname))
			}
		}
		rows.Close()
		db.Close()
	}
	return nil
}

// RunJanitor sweeps expired leases and drops the corresponding Postgres users.
func (s *DBStore) RunJanitor(ctx context.Context) error {
	leases, err := s.db.Scan("secrets/db/leases/")
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for key, data := range leases {
		plain, err := s.crypto.Decrypt(key, data)
		if err != nil {
			continue
		}
		var lease DBLease
		if err := json.Unmarshal(plain, &lease); err != nil {
			continue
		}
		if now.After(lease.ExpiresAt) {
			_ = s.dropUser(ctx, lease.DBConfig, lease.Username, lease.LeaseID)
		}
	}
	return nil
}

func (s *DBStore) dropUser(ctx context.Context, configName, username, leaseID string) error {
	cfg, err := s.loadConfig(configName)
	if err != nil {
		return err
	}
	connStr := fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=require",
		cfg.Host, cfg.Port, cfg.DBName, cfg.AdminUser, cfg.AdminPassword)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.ExecContext(ctx, fmt.Sprintf("DROP USER IF EXISTS %s;", username))
	if err != nil {
		return fmt.Errorf("drop user %s: %w", username, err)
	}
	return s.db.Delete("secrets/db/leases/" + leaseID)
}

func (s *DBStore) loadConfig(name string) (*DBConfig, error) {
	data, err := s.db.Get("secrets/db/" + name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("db config %q not found", name)
		}
		return nil, err
	}
	plain, err := s.crypto.Decrypt("secrets/db/"+name, data)
	if err != nil {
		return nil, err
	}
	var cfg DBConfig
	return &cfg, json.Unmarshal(plain, &cfg)
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func replaceAll(s, old, new string) string {
	result := s
	for {
		replaced := ""
		idx := 0
		for i := 0; i < len(result); i++ {
			if i+len(old) <= len(result) && result[i:i+len(old)] == old {
				replaced += result[idx:i] + new
				i += len(old) - 1
				idx = i + 1
			}
		}
		replaced += result[idx:]
		if replaced == result {
			break
		}
		result = replaced
	}
	return result
}
