# Development

Use this guide when changing the codebase.

## Code Layout

```text
cmd/lockr             Cobra CLI and CLI HTTP client
internal/server       server startup and subsystem wiring
internal/api          HTTP routes, middleware, and handlers
internal/auth         admin, user, session, Ed25519, and TOTP auth
internal/policy       YAML policy engine with built-in policies
internal/secrets      KV, transit, and DB secret engines
internal/storage      BadgerDB and encryption helpers
internal/audit        audit logging
internal/config       YAML config loading
pkg/client            Go SDK
examples              Go, Node.js, and Python examples
deployments           Docker assets
test/e2e.sh           End-to-end test suite
docs                  task-based documentation
```

## Useful Commands

```bash
go build ./...
go build -o lockr ./cmd/lockr
go test ./...
go vet ./...
```

If the Go cache is not writable:

```bash
GOCACHE=/tmp/lockr-gocache go test ./...
```

## Local Dev Loop

```bash
go build -o lockr ./cmd/lockr
./lockr server --dev
```

In another terminal:

```bash
./lockr status --addr http://localhost:8300
```

## E2E Test Suite

Run against a live production server:

```bash
export LOCKR_TOKEN=<admin-token>
export LOCKR_CA=/etc/lockr/tls/ca.crt
./test/e2e.sh
```

Optional overrides:

```bash
LOCKR_ADDR=https://myserver:8300 LOCKR_BIN=./lockr ./test/e2e.sh
```

All test data is prefixed with `e2e-` and cleaned up on exit.

## Auth Storage Prefixes

```text
auth/users/<username>          UserRecord (username, policy, Argon2id hash)
auth/services/<name>           ServiceRecord (name, public key, policy)
auth/services/totp/<name>      TOTPRecord
auth/admins/<name>             AdminRecord (name, policy, Argon2id hash)
auth/sessions/<sha256(token)>  SessionMeta (identity, auth_method, policy, expiry)
```

## Secret Storage Prefixes

```text
secrets/kv/<path>/__meta
secrets/kv/<path>/v<N>
secrets/transit/<key>
secrets/db/<name>
secrets/db/leases/<lease-id>
audit/<timestamp>/<ulid>
```

## Identity Prefix Convention

Sessions carry an identity string with a type prefix:

```text
user:<username>   — password-authenticated user
svc:<name>        — Ed25519 or TOTP service
admin:<name>      — admin token holder
```

This prefix appears in audit log entries and `whoami` responses.

## Built-in Policies

Three policies are baked into the policy engine and require no YAML files:

```text
readonly   — read, list on secrets/kv/*
readwrite  — read, write, delete, list on secrets/kv/* + encrypt, decrypt on secrets/transit/*
admin      — full access to kv, transit, and db engines
```

A YAML file with the same name overrides the built-in.

## Implementation Notes

- Policies are file-backed YAML loaded into memory. Built-in policies are always available as fallbacks.
- BadgerDB stores auth records, sessions, secret metadata, encrypted secret records, leases, and audit entries.
- Secret values are encrypted with AES-256-GCM before storage using HKDF-derived per-path keys.
- Service auth uses Ed25519 challenge-response. Challenges are one-time use and expire in 60 seconds.
- Session tokens store verification metadata only — plaintext tokens are never persisted.
- Login attempts (success and failure) are written to the audit log even though auth routes are unauthenticated.
- Dev mode bypasses authentication and grants `root`.

## Known Gaps

- Admin and service operations should be separated more clearly.
- mTLS client certificate authentication is not implemented.
- KV restore and purge APIs are not implemented.
- Master-key canary verification is not implemented.
- Test coverage is limited to auth and policy unit tests — API handler tests are not yet written.

## Documentation Rule

When adding or changing a user-facing feature, update the matching file under `docs/`. Keep `PRODUCT.md` as the high-level product reference and `docs/` as the task-level guide.
