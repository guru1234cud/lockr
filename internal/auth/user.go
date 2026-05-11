package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/etherance/lockr/internal/storage"
)

type UserRecord struct {
	Username  string    `json:"username"`
	Policy    string    `json:"policy"`
	CreatedAt time.Time `json:"created_at"`
	Hash      []byte    `json:"hash"`
	Disabled  bool      `json:"disabled"`
}

type UserAuth struct {
	db *storage.DB
}

func NewUserAuth(db *storage.DB) *UserAuth {
	return &UserAuth{db: db}
}

func (a *UserAuth) Create(username, password, policy string) error {
	if _, err := a.db.Get("auth/users/" + username); err == nil {
		return fmt.Errorf("user %q already exists", username)
	}
	hash, err := storage.HashArgon2id([]byte(password))
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	rec := UserRecord{
		Username:  username,
		Policy:    policy,
		CreatedAt: time.Now().UTC(),
		Hash:      hash,
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return a.db.Set("auth/users/"+username, data)
}

func (a *UserAuth) Verify(username, password string) (*UserRecord, error) {
	rec, err := a.Get(username)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}
	if rec.Disabled {
		return nil, errors.New("invalid credentials")
	}
	if !storage.VerifyArgon2id([]byte(password), rec.Hash) {
		return nil, errors.New("invalid credentials")
	}
	return rec, nil
}

func (a *UserAuth) Get(username string) (*UserRecord, error) {
	data, err := a.db.Get("auth/users/" + username)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("user %q not found", username)
		}
		return nil, err
	}
	var rec UserRecord
	return &rec, json.Unmarshal(data, &rec)
}

func (a *UserAuth) List() ([]UserRecord, error) {
	keys, err := a.db.List("auth/users/")
	if err != nil {
		return nil, err
	}
	var users []UserRecord
	for _, key := range keys {
		data, err := a.db.Get(key)
		if err != nil {
			continue
		}
		var rec UserRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			continue
		}
		rec.Hash = nil
		users = append(users, rec)
	}
	return users, nil
}

func (a *UserAuth) Delete(username string) error {
	if _, err := a.db.Get("auth/users/" + username); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("user %q not found", username)
		}
		return err
	}
	return a.db.Delete("auth/users/" + username)
}

func (a *UserAuth) ChangePolicy(username, policy string) error {
	rec, err := a.Get(username)
	if err != nil {
		return err
	}
	rec.Policy = policy
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return a.db.Set("auth/users/"+username, data)
}

func (a *UserAuth) ChangePassword(username, newPassword string) error {
	rec, err := a.Get(username)
	if err != nil {
		return err
	}
	hash, err := storage.HashArgon2id([]byte(newPassword))
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	rec.Hash = hash
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return a.db.Set("auth/users/"+username, data)
}
