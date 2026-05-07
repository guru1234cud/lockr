package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/etherance/lockr/internal/storage"
)

const adminTokenPrefix = "lkat_"

type AdminRecord struct {
	Name      string    `json:"name"`
	Policy    string    `json:"policy"`
	CreatedAt time.Time `json:"created_at"`
	Hash      []byte    `json:"hash"` // Argon2id hash
}

type AdminAuth struct {
	db *storage.DB
}

func NewAdminAuth(db *storage.DB) *AdminAuth {
	return &AdminAuth{db: db}
}

func (a *AdminAuth) HasAdmins() (bool, error) {
	keys, err := a.db.List("auth/admins/")
	if err != nil {
		return false, err
	}
	return len(keys) > 0, nil
}

// Create generates a new admin token, stores its hash, and returns the raw token.
func (a *AdminAuth) Create(name, policy string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate admin token: %w", err)
	}
	token := adminTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)

	hash, err := storage.HashArgon2id([]byte(token))
	if err != nil {
		return "", fmt.Errorf("hash admin token: %w", err)
	}

	rec := AdminRecord{
		Name:      name,
		Policy:    policy,
		CreatedAt: time.Now().UTC(),
		Hash:      hash,
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	if err := a.db.Set("auth/admins/"+name, data); err != nil {
		return "", err
	}
	return token, nil
}

// Verify checks an admin token against all stored admin records.
func (a *AdminAuth) Verify(token string) (*AdminRecord, error) {
	if len(token) < len(adminTokenPrefix) || token[:len(adminTokenPrefix)] != adminTokenPrefix {
		return nil, errors.New("invalid admin token format")
	}

	keys, err := a.db.List("auth/admins/")
	if err != nil {
		return nil, err
	}

	for _, key := range keys {
		data, err := a.db.Get(key)
		if err != nil {
			continue
		}
		var rec AdminRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			continue
		}
		if storage.VerifyArgon2id([]byte(token), rec.Hash) {
			return &rec, nil
		}
	}
	return nil, errors.New("invalid admin token")
}

// Delete removes an admin token by name.
func (a *AdminAuth) Delete(name string) error {
	if _, err := a.db.Get("auth/admins/" + name); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("admin %q not found", name)
		}
		return err
	}
	return a.db.Delete("auth/admins/" + name)
}

func (a *AdminAuth) Get(name string) (*AdminRecord, error) {
	data, err := a.db.Get("auth/admins/" + name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("admin %q not found", name)
		}
		return nil, err
	}
	var rec AdminRecord
	return &rec, json.Unmarshal(data, &rec)
}
