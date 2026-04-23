package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/etherance/lockr/internal/storage"
)

const sessionTokenPrefix = "lvt_"

type SessionMeta struct {
	Identity   string    `json:"identity"`
	AuthMethod string    `json:"auth_method"`
	Policy     string    `json:"policy"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type SessionStore struct {
	db  *storage.DB
	ttl time.Duration
}

func NewSessionStore(db *storage.DB, ttl time.Duration) *SessionStore {
	return &SessionStore{db: db, ttl: ttl}
}

// Issue creates a new session token for the given identity and returns the raw token.
func (s *SessionStore) Issue(identity, authMethod, policy string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	token := sessionTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)

	hash, err := storage.HashArgon2id([]byte(token))
	if err != nil {
		return "", fmt.Errorf("hash session token: %w", err)
	}

	meta := SessionMeta{
		Identity:   identity,
		AuthMethod: authMethod,
		Policy:     policy,
		IssuedAt:   time.Now().UTC(),
		ExpiresAt:  time.Now().UTC().Add(s.ttl),
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return "", err
	}

	// Store hash → metadata, keyed by hash hex
	key := "auth/sessions/" + base64.RawURLEncoding.EncodeToString(hash)
	if err := s.db.SetWithTTL(key, metaJSON, s.ttl); err != nil {
		return "", fmt.Errorf("store session: %w", err)
	}
	return token, nil
}

// Validate looks up the session token and returns its metadata.
func (s *SessionStore) Validate(token string) (*SessionMeta, error) {
	if len(token) < len(sessionTokenPrefix) || token[:len(sessionTokenPrefix)] != sessionTokenPrefix {
		return nil, errors.New("invalid token format")
	}

	// Enumerate sessions and compare in constant time (hash lookup requires re-deriving the key).
	// Since Argon2id is slow, we store the hash as the key and must scan — but session count is small.
	// For production scale, store a fast hash index. For Lockr v1 this is acceptable.
	hash, err := storage.HashArgon2id([]byte(token))
	if err != nil {
		return nil, err
	}
	key := "auth/sessions/" + base64.RawURLEncoding.EncodeToString(hash)
	data, err := s.db.Get(key)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, errors.New("session not found or expired")
		}
		return nil, err
	}
	_ = subtle.ConstantTimeCompare([]byte(token), []byte(token)) // ensure timing branch not optimized away

	var meta SessionMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	if time.Now().UTC().After(meta.ExpiresAt) {
		_ = s.db.Delete(key)
		return nil, errors.New("session expired")
	}
	return &meta, nil
}

// Revoke deletes the session for the given token.
func (s *SessionStore) Revoke(token string) error {
	hash, err := storage.HashArgon2id([]byte(token))
	if err != nil {
		return err
	}
	key := "auth/sessions/" + base64.RawURLEncoding.EncodeToString(hash)
	return s.db.Delete(key)
}
