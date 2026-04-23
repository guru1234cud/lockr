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
	Name              string        `json:"name"`
	Host              string        `json:"host"`
	Port              int           `json:"port"`
	DBName            string        `json:"dbname"`
	AdminUser         string        `json:"admin_user"`
	AdminPassword     string        `json:"admin_password"` // stored encrypted
	DefaultTTL        time.Duration `json:"default_ttl"`
	MaxTTL            time.Duration `json:"max_ttl"`
	CreationStatement string        `json:"creation_statement"`
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

	stmt := cfg.CreationStatement
	if stmt == "" {
		stmt = fmt.Sprintf(
			"CREATE USER %s WITH PASSWORD '%s'; GRANT CONNECT ON DATABASE %s TO %s;",
			username, password, cfg.DBName, username,
		)
	} else {
		// Replace template vars.
		stmt = replaceAll(stmt, "{{username}}", username)
		stmt = replaceAll(stmt, "{{password}}", password)
	}

	if _, err := db.ExecContext(ctx, stmt); err != nil {
		return nil, fmt.Errorf("create postgres user: %w", err)
	}

	ttl := cfg.DefaultTTL
	if ttl == 0 {
		ttl = time.Hour
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
	if err := s.db.SetWithTTL("secrets/db/leases/"+lease.LeaseID, data, ttl+time.Minute); err != nil {
		return nil, err
	}
	return lease, nil
}

// RevokeLease drops the Postgres user and removes the lease.
func (s *DBStore) RevokeLease(ctx context.Context, leaseID string) error {
	data, err := s.db.Get("secrets/db/leases/" + leaseID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("lease %q not found", leaseID)
		}
		return err
	}
	var lease DBLease
	if err := json.Unmarshal(data, &lease); err != nil {
		return err
	}
	return s.dropUser(ctx, lease.DBConfig, lease.Username, leaseID)
}

// RunJanitor sweeps expired leases and drops the corresponding Postgres users.
func (s *DBStore) RunJanitor(ctx context.Context) error {
	leases, err := s.db.Scan("secrets/db/leases/")
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, data := range leases {
		var lease DBLease
		if err := json.Unmarshal(data, &lease); err != nil {
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
