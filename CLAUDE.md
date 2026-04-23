# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Lockr is a self-hosted, bare-minimum secrets manager for small dev teams and startups. It runs as a single Go binary backed by an embedded BadgerDB store — no external database, no cloud dependencies.

## Tech Stack

- **Language**: Go (latest stable)
- **Storage**: BadgerDB v4 (`github.com/dgraph-io/badger/v4`) — embedded LSM-tree KV store
- **Transport**: TLS 1.3 only (plain HTTP in dev mode only)
- **Config**: YAML
- **IDs**: ULID (`github.com/oklog/ulid/v2`) for request IDs, audit IDs, lease IDs
- **Crypto**: Go stdlib (`crypto/ed25519`, `crypto/aes`, `crypto/tls`) + `golang.org/x/crypto` (Argon2id, HKDF)

## Build & Dev Commands

```bash
go build ./...                      # build all packages
go build -o lockr ./cmd/lockr       # build the binary
go test ./...                       # run all tests
go test ./internal/auth/...         # run tests for a specific package
go vet ./...                        # vet
golangci-lint run                   # lint (if installed)
make build                          # build via Makefile (once written)
make test                           # test via Makefile
```

Dev mode (no TLS, no auth, in-memory BadgerDB — data wiped on restart):
```bash
./lockr server --dev
```

## Project Structure

```
cmd/lockr/main.go                   # CLI entrypoint (cobra)
internal/
  server/server.go                  # HTTP server, TLS config, middleware wiring
  api/
    router.go                       # Route registration (/v1/...)
    middleware.go                   # Auth, request ID injection, logging
    auth_handlers.go
    kv_handlers.go
    db_handlers.go
    transit_handlers.go
    sys_handlers.go
  auth/
    ed25519.go                      # Challenge-response (primary auth)
    totp.go                         # TOTP fallback (RFC 6238)
    admin.go                        # Long-lived admin tokens (Argon2id-hashed)
    session.go                      # Session token issuance + validation
  secrets/
    kv.go                           # KV static secrets, versioning (last 5), soft delete
    db.go                           # Postgres dynamic creds + background janitor goroutine
    transit.go                      # AES-256-GCM encrypt/decrypt-as-a-service, key rotation
  storage/
    badger.go                       # BadgerDB wrapper (Open/Close/Get/Set/Delete/List/Scan)
    crypto.go                       # AES-256-GCM, Argon2id, HKDF key derivation, master key
  policy/policy.go                  # YAML policy loader, wildcard path matcher, hot-reload on SIGHUP
  audit/audit.go                    # Dual-write: BadgerDB (queryable) + append-only audit.log
  config/config.go                  # YAML config loader + validation
pkg/client/client.go                # Go client library (thin HTTP wrapper)
deployments/
  Dockerfile
  docker-compose.yml
examples/
  python/                           # Python usage example
  nodejs/                           # Node.js usage example
  go/                               # Go usage example
policies/example-policy.yaml
config.example.yml
```

## Architecture

### Request Flow
HTTP request → TLS → middleware (request ID, auth, policy check) → handler → storage

### Authentication (4 layers)
1. **Ed25519 challenge-response** (primary): server sends 32-byte challenge → client signs with private key → server verifies against stored public key → issues session token (1hr TTL)
2. **TOTP** (fallback): RFC 6238, ±1 window clock skew tolerance, no DB lookup for verify
3. **Admin token**: Argon2id-hashed, long-lived, policy-scoped, full audit trail
4. **Dev mode**: `--dev` flag only — no auth, no TLS, in-memory storage, loud banner

### Encryption at Rest
- All secret values individually encrypted with **AES-256-GCM** before writing to BadgerDB
- Master key (256-bit random) encrypted at rest: `Argon2id(passphrase)` → AES-256-GCM → `master.key.enc`
- Per-path keys derived from master key using **HKDF-SHA256** with path as info parameter
- Passphrase: `LOCKR_PASSPHRASE` env var → interactive prompt
- Canary value at `meta/master_key_check` to verify correct decryption on startup

### BadgerDB Key Prefixes
```
secrets/kv/<path>           KV entries (encrypted)
secrets/db/<name>           DB dynamic credential configs (encrypted)
secrets/transit/<keyname>   Transit encryption keys (encrypted)
auth/services/<name>        Ed25519 public keys + TOTP secrets
auth/admins/<name>          Admin token hashes
auth/sessions/<token_hash>  Active sessions with TTL
policy/<name>               Policy definitions
audit/<timestamp>/<ulid>    Audit entries
meta/master_key_check       Decryption canary
```

### On-Disk Layout
```
/var/lib/lockr/
├── data/             BadgerDB directory
├── audit.log         Append-only newline-delimited JSON (never modified)
├── master.key.enc    Argon2id-derived + AES-256-GCM encrypted master key
└── config.yml
```

### Policy Engine
- YAML files in `/etc/lockr/policies/` (version-controllable)
- Capabilities: `read`, `write`, `delete`, `list`, `encrypt`, `decrypt`
- Wildcard paths: `secrets/kv/prod/*` matches all paths under `prod/`
- Explicit deny overrides allow; default deny if no rule matches
- Hot-reload on SIGHUP (atomic swap of in-memory policy map, no restart)

### API Envelope
All `/v1/` responses:
```json
{ "data": {}, "error": null, "request_id": "01HXYZ..." }
```

### Session Tokens
Format: `lvt_<base64url(32 random bytes)>`. Only the Argon2id hash is stored in BadgerDB.

## Critical Implementation Rules

- **Timing-safe comparisons**: always use `crypto/subtle.ConstantTimeCompare` — never `==` for secrets/tokens
- **Memory zeroing**: zero plaintext values after encryption on all code paths (use `defer`)
- **Secret values never logged**: not in plaintext, not encrypted — never in audit log
- **TLS 1.3 only**: `tls.Config.MinVersion = tls.VersionTLS13`
- **Go stdlib crypto first**: use `crypto/ed25519`, `crypto/aes`, `crypto/rand` from stdlib before reaching for external packages
- **Dev mode guard**: `--dev` must disable TLS, disable auth middleware, use `badger.WithInMemory(true)`, and print a loud `[DEV MODE — NOT FOR PRODUCTION]` banner

## Build Order

When implementing from scratch, follow this order:
1. `internal/storage/badger.go` — BadgerDB wrapper
2. `internal/storage/crypto.go` — crypto primitives + master key
3. `cmd/lockr/main.go` — cobra CLI skeleton
4. `lockr init` command
5. `internal/auth/ed25519.go` + `internal/auth/session.go`
6. `internal/policy/policy.go`
7. `internal/api/` — HTTP server + KV handlers
8. `lockr enroll` + `lockr get` + `lockr set` working end-to-end
9. `internal/secrets/db.go` + DB handlers + janitor goroutine
10. `internal/secrets/transit.go` + transit handlers
11. `internal/auth/totp.go` + `internal/auth/admin.go`
12. `internal/audit/audit.go`
13. Dev mode
14. `pkg/client/client.go`
15. Examples, Dockerfile, docker-compose.yml

## Out of Scope for v1

Do not implement: cloud auth/secrets (AWS/GCP/Azure), LDAP/OIDC/SAML, external storage backends, replication, namespaces/multi-tenancy, Web UI, MySQL dynamic creds, auto-rotation of static secrets, HSM, ACME/Let's Encrypt, any enterprise features.
