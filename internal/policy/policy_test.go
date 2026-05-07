package policy

import (
	"testing"
)

func makeEngine(t *testing.T, policies ...*Policy) *Engine {
	t.Helper()
	e := NewEngine("")
	for _, p := range policies {
		e.SetPolicy(p)
	}
	return e
}

func TestPolicyRootGrantsAll(t *testing.T) {
	e := makeEngine(t)
	caps := []Capability{CapRead, CapWrite, CapDelete, CapList, CapEncrypt, CapDecrypt}
	for _, cap := range caps {
		if !e.Allowed("root", "secrets/kv/anything", cap) {
			t.Errorf("root policy denied %s", cap)
		}
	}
}

func TestPolicyUnknownDeniesAll(t *testing.T) {
	e := makeEngine(t)
	if e.Allowed("nonexistent", "secrets/kv/path", CapRead) {
		t.Fatal("unknown policy should deny")
	}
}

func TestPolicyAllowsMatchingRule(t *testing.T) {
	e := makeEngine(t, &Policy{
		Name: "svc",
		Rules: []Rule{
			{Path: "secrets/kv/prod/db", Capabilities: []Capability{CapRead}},
		},
	})

	if !e.Allowed("svc", "secrets/kv/prod/db", CapRead) {
		t.Fatal("should be allowed")
	}
}

func TestPolicyDeniesUnmatchedPath(t *testing.T) {
	e := makeEngine(t, &Policy{
		Name: "svc",
		Rules: []Rule{
			{Path: "secrets/kv/prod/db", Capabilities: []Capability{CapRead}},
		},
	})

	if e.Allowed("svc", "secrets/kv/prod/other", CapRead) {
		t.Fatal("unmatched path should be denied")
	}
}

func TestPolicyDeniesUnmatchedCapability(t *testing.T) {
	e := makeEngine(t, &Policy{
		Name: "svc",
		Rules: []Rule{
			{Path: "secrets/kv/prod/db", Capabilities: []Capability{CapRead}},
		},
	})

	if e.Allowed("svc", "secrets/kv/prod/db", CapWrite) {
		t.Fatal("write should be denied when only read is granted")
	}
}

func TestPolicyWildcardMatchesSubpaths(t *testing.T) {
	e := makeEngine(t, &Policy{
		Name: "svc",
		Rules: []Rule{
			{Path: "secrets/kv/prod/*", Capabilities: []Capability{CapRead, CapWrite}},
		},
	})

	cases := []string{
		"secrets/kv/prod/db",
		"secrets/kv/prod/api/key",
	}
	for _, path := range cases {
		if !e.Allowed("svc", path, CapRead) {
			t.Errorf("wildcard should allow read on %s", path)
		}
	}
}

func TestPolicyWildcardDoesNotMatchParent(t *testing.T) {
	e := makeEngine(t, &Policy{
		Name: "svc",
		Rules: []Rule{
			{Path: "secrets/kv/prod/*", Capabilities: []Capability{CapRead}},
		},
	})

	if e.Allowed("svc", "secrets/kv/staging/db", CapRead) {
		t.Fatal("wildcard for prod should not match staging")
	}
}

func TestPolicyExplicitDenyOverridesAllow(t *testing.T) {
	e := makeEngine(t, &Policy{
		Name: "svc",
		Rules: []Rule{
			{Path: "secrets/kv/prod/*", Capabilities: []Capability{CapRead}},
			{Path: "secrets/kv/prod/secret", Deny: true},
		},
	})

	if e.Allowed("svc", "secrets/kv/prod/secret", CapRead) {
		t.Fatal("explicit deny should override wildcard allow")
	}
	if !e.Allowed("svc", "secrets/kv/prod/other", CapRead) {
		t.Fatal("non-denied path under wildcard should still be allowed")
	}
}

func TestPolicyMultipleCapabilities(t *testing.T) {
	e := makeEngine(t, &Policy{
		Name: "svc",
		Rules: []Rule{
			{Path: "secrets/transit/mykey", Capabilities: []Capability{CapEncrypt, CapDecrypt}},
		},
	})

	if !e.Allowed("svc", "secrets/transit/mykey", CapEncrypt) {
		t.Fatal("encrypt should be allowed")
	}
	if !e.Allowed("svc", "secrets/transit/mykey", CapDecrypt) {
		t.Fatal("decrypt should be allowed")
	}
	if e.Allowed("svc", "secrets/transit/mykey", CapWrite) {
		t.Fatal("write should be denied")
	}
}

func TestPolicySetPolicyReplaces(t *testing.T) {
	e := makeEngine(t, &Policy{
		Name:  "svc",
		Rules: []Rule{{Path: "secrets/kv/old", Capabilities: []Capability{CapRead}}},
	})

	e.SetPolicy(&Policy{
		Name:  "svc",
		Rules: []Rule{{Path: "secrets/kv/new", Capabilities: []Capability{CapRead}}},
	})

	if e.Allowed("svc", "secrets/kv/old", CapRead) {
		t.Fatal("old path should no longer be allowed after policy replacement")
	}
	if !e.Allowed("svc", "secrets/kv/new", CapRead) {
		t.Fatal("new path should be allowed after policy replacement")
	}
}
