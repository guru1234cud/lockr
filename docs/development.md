# Development

Use this guide when changing the codebase.

## Code Layout

```text
cmd/lockr             Cobra CLI and CLI HTTP client
internal/server       server startup and subsystem wiring
internal/api          HTTP routes, middleware, and handlers
internal/auth         admin, session, Ed25519, and TOTP auth
internal/policy       YAML policy engine
internal/secrets      KV, transit, and DB secret engines
internal/storage      BadgerDB and encryption helpers
internal/audit        audit logging
internal/config       YAML config loading
pkg/client            Go SDK
examples              Go, Node.js, and Python examples
deployments           Docker assets
policies              example policy files
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

## Implementation Notes

- Policies are file-backed YAML and loaded into memory.
- BadgerDB stores auth records, sessions, secret metadata, encrypted secret records, leases, and audit entries.
- Secret records are encrypted before storage.
- Service auth uses Ed25519 challenge-response.
- Session tokens store verification metadata, not plaintext tokens.
- Dev mode bypasses authentication and grants `root`.

## Known Gaps

Do not document these as finished behavior:

- Some sensitive DB and transit routes still need stricter policy enforcement.
- Admin and service operations should be separated more clearly.
- CLI TLS currently allows insecure verification when no CA is provided.
- mTLS client certificate authentication is not implemented.
- KV restore and purge APIs are not implemented.
- Master-key canary verification is not implemented.
- Test coverage is still limited.

## Documentation Rule

When adding or changing a user-facing task, update the matching file under `docs/`. Keep `PRODUCT.md` as the high-level product reference and `docs/` as the task-level guide.
