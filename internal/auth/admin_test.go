package auth

import (
	"strings"
	"testing"
)

func TestAdminHasAdmins(t *testing.T) {
	db := openTestDB(t)
	admins := NewAdminAuth(db)

	hasAdmins, err := admins.HasAdmins()
	if err != nil {
		t.Fatalf("HasAdmins() error = %v", err)
	}
	if hasAdmins {
		t.Fatal("HasAdmins() = true, want false")
	}

	if _, err := admins.Create("root", "admin"); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	hasAdmins, err = admins.HasAdmins()
	if err != nil {
		t.Fatalf("HasAdmins() after Create() error = %v", err)
	}
	if !hasAdmins {
		t.Fatal("HasAdmins() after Create() = false, want true")
	}
}

func TestAdminCreateReturnsToken(t *testing.T) {
	db := openTestDB(t)
	admins := NewAdminAuth(db)

	token, err := admins.Create("ops", "admin")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !strings.HasPrefix(token, adminTokenPrefix) {
		t.Fatalf("token %q missing prefix %q", token, adminTokenPrefix)
	}
}

func TestAdminVerifyReturnsRecord(t *testing.T) {
	db := openTestDB(t)
	admins := NewAdminAuth(db)

	token, err := admins.Create("ops", "admin")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	rec, err := admins.Verify(token)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if rec.Name != "ops" {
		t.Fatalf("Name = %q, want ops", rec.Name)
	}
	if rec.Policy != "admin" {
		t.Fatalf("Policy = %q, want admin", rec.Policy)
	}
}

func TestAdminVerifyRejectsWrongToken(t *testing.T) {
	db := openTestDB(t)
	admins := NewAdminAuth(db)

	if _, err := admins.Create("ops", "admin"); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if _, err := admins.Verify(adminTokenPrefix + "wrongtoken"); err == nil {
		t.Fatal("Verify() error = nil, want error for wrong token")
	}
}

func TestAdminVerifyRejectsBadPrefix(t *testing.T) {
	db := openTestDB(t)
	admins := NewAdminAuth(db)

	if _, err := admins.Verify("notavalidtoken"); err == nil {
		t.Fatal("Verify() error = nil, want error for bad prefix")
	}
}

func TestAdminDelete(t *testing.T) {
	db := openTestDB(t)
	admins := NewAdminAuth(db)

	token, err := admins.Create("ops", "admin")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if err := admins.Delete("ops"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	if _, err := admins.Verify(token); err == nil {
		t.Fatal("Verify() after Delete() error = nil, want error")
	}
}

func TestAdminDeleteNotFound(t *testing.T) {
	db := openTestDB(t)
	admins := NewAdminAuth(db)

	if err := admins.Delete("nonexistent"); err == nil {
		t.Fatal("Delete() error = nil, want error for missing admin")
	}
}
