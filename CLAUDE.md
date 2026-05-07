# Claude Code Guide

Use this file as the short working guide for Claude Code. Use `PRODUCT.md` for product-level context and `docs/README.md` for task-level user documentation.

## Project Map

Lockr is a Go secrets manager with:

- CLI: `cmd/lockr`
- HTTP API: `internal/api`
- server wiring: `internal/server`
- auth: `internal/auth`
- secret engines: `internal/secrets`
- BadgerDB and crypto helpers: `internal/storage`
- YAML policy engine: `internal/policy`
- Go SDK: `pkg/client`
- task documentation: `docs`

## Claude Code Workflow

1. Check the worktree before editing:

```bash
git status --short
```

2. Read the relevant files before changing behavior.
3. Keep edits scoped to the requested task.
4. Do not revert user changes or unrelated modified files.
5. Update the matching `docs/*.md` file when changing user-facing behavior.
6. Run the smallest useful verification command before finishing.

## Common Commands

```bash
go build ./...
go build -o lockr ./cmd/lockr
go test ./...
go vet ./...
```

If the default Go cache is not writable:

```bash
GOCACHE=/tmp/lockr-gocache go test ./...
```

Local dev server:

```bash
./lockr server --dev
```

## Auth Model

Service auth uses Ed25519 challenge-response:

```text
/v1/auth/challenge -> client signs challenge -> /v1/auth/verify -> lvt_ session token
```

CLI service commands can authenticate with:

```bash
--identity <service> --key <ed25519-private-key>
```

Admin commands use:

```bash
--token <lkat-admin-token>
```

Dev mode bypasses auth and grants `root`.

## Policy Model

Policies are YAML files loaded from the server policy directory, usually:

```text
/etc/lockr/policies
```

Policies are not stored in BadgerDB and are not stored on the client. Services and sessions only carry the policy name.

Policy checks call:

```go
s.policy.Allowed(getPolicy(r), path, capability)
```

Default behavior is deny unless a matching rule grants the required capability. Explicit deny rules override allow rules.

## Storage Prefixes

```text
auth/services/<name>
auth/services/totp/<name>
auth/admins/<name>
auth/sessions/<token-lookup>
secrets/kv/<path>/__meta
secrets/kv/<path>/v<N>
secrets/transit/<key>
secrets/db/<name>
secrets/db/leases/<lease-id>
audit/<timestamp>/<ulid>
```

## Documentation Rules

- Keep `PRODUCT.md` high level.
- Keep `docs/` task based and easy to follow.
- Prefer one task per file.
- When documenting security-sensitive behavior, mention current limitations clearly.
- Do not document planned behavior as if it already works.

## Known Gaps

- Tighten policy checks for sensitive DB/transit operations.
- Separate admin-only operations from service operations.
- Make CLI TLS verification explicit instead of silently insecure.
- Add tests around auth, policy, KV, transit, and API middleware.
