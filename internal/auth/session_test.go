package auth

import (
	"testing"
	"time"

	"github.com/etherance/lockr/internal/storage"
)

func TestSessionIssueAndValidate(t *testing.T) {
	db := openTestDB(t)
	store := NewSessionStore(db, time.Hour)

	token, err := store.Issue("api-server", "ed25519", "api-policy")
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	meta, err := store.Validate(token)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if meta.Identity != "api-server" {
		t.Fatalf("Identity = %q, want api-server", meta.Identity)
	}
	if meta.AuthMethod != "ed25519" {
		t.Fatalf("AuthMethod = %q, want ed25519", meta.AuthMethod)
	}
	if meta.Policy != "api-policy" {
		t.Fatalf("Policy = %q, want api-policy", meta.Policy)
	}
	if len(meta.TokenHash) == 0 {
		t.Fatal("TokenHash is empty")
	}
}

func TestSessionValidateRejectsWrongToken(t *testing.T) {
	db := openTestDB(t)
	store := NewSessionStore(db, time.Hour)

	if _, err := store.Issue("api-server", "ed25519", "api-policy"); err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if _, err := store.Validate("lvt_wrong-token"); err == nil {
		t.Fatal("Validate() error = nil, want error")
	}
}

func TestSessionRevoke(t *testing.T) {
	db := openTestDB(t)
	store := NewSessionStore(db, time.Hour)

	token, err := store.Issue("api-server", "ed25519", "api-policy")
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if err := store.Revoke(token); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	if _, err := store.Validate(token); err == nil {
		t.Fatal("Validate() after revoke error = nil, want error")
	}
}

func TestSessionExpires(t *testing.T) {
	db := openTestDB(t)
	store := NewSessionStore(db, 10*time.Millisecond)

	token, err := store.Issue("api-server", "ed25519", "api-policy")
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	if _, err := store.Validate(token); err == nil {
		t.Fatal("Validate() after expiry error = nil, want error")
	}
}

func openTestDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(storage.Options{InMemory: true})
	if err != nil {
		t.Fatalf("storage.Open() error = %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("db.Close() error = %v", err)
		}
	})
	return db
}
