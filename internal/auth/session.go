package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	TokenHash  []byte    `json:"token_hash"`
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

	now := time.Now().UTC()
	meta := SessionMeta{
		Identity:   identity,
		AuthMethod: authMethod,
		Policy:     policy,
		IssuedAt:   now,
		ExpiresAt:  now.Add(s.ttl),
		TokenHash:  hash,
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return "", err
	}

	key := sessionKey(token)
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

	key := sessionKey(token)
	data, err := s.db.Get(key)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, errors.New("session not found or expired")
		}
		return nil, err
	}

	var meta SessionMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	if !storage.VerifyArgon2id([]byte(token), meta.TokenHash) {
		return nil, errors.New("invalid session token")
	}
	if time.Now().UTC().After(meta.ExpiresAt) {
		_ = s.db.Delete(key)
		return nil, errors.New("session expired")
	}
	return &meta, nil
}

// Revoke deletes the session for the given token.
func (s *SessionStore) Revoke(token string) error {
	return s.db.Delete(sessionKey(token))
}

func sessionKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "auth/sessions/" + hex.EncodeToString(sum[:])
}
