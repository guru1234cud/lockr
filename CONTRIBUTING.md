# Contributing to Lockr

Thank you for your interest in contributing. This guide covers how to set up the project, run tests, and submit changes.

---

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Layout](#project-layout)
- [Running Tests](#running-tests)
- [Making Changes](#making-changes)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Reporting Bugs](#reporting-bugs)
- [Security Issues](#security-issues)

---

## Getting Started

**Prerequisites:**

- Go 1.25 or later
- Git
- Docker (optional, for deployment testing)

**Fork and clone:**

```bash
# Fork the repo on GitHub, then:
git clone https://github.com/<your-username>/lockr.git
cd lockr
```

**Install dependencies:**

```bash
go mod download
```

---

## Development Setup

**Build the binary:**

```bash
go build -o lockr ./cmd/lockr
# or
make build
```

**Start a local dev server:**

```bash
./lockr server --dev
# or
make dev
```

Dev mode uses HTTP, in-memory storage, and no authentication. It is safe for local testing and does not require initialization.

**Create a dev admin token:**

```bash
./lockr admin create --name root --addr http://localhost:8300
```

**Verify the server is running:**

```bash
curl http://localhost:8300/v1/sys/health
```

---

## Project Layout

```
cmd/lockr/          CLI entrypoint and all commands
internal/api/       HTTP handlers, router, middleware
internal/auth/      Session store, Ed25519, admin tokens, TOTP
internal/secrets/   KV, transit, and dynamic DB secret engines
internal/storage/   BadgerDB wrapper and AES-GCM crypto helpers
internal/policy/    YAML policy engine
internal/audit/     Audit logger
internal/config/    Config loading
internal/server/    Server wiring and startup
pkg/client/         Public Go SDK
examples/           Working examples in Go, Python, and Node.js
docs/               Task-based user documentation
deployments/        Dockerfile and Docker Compose
policies/           Example policy files
```

See [docs/development.md](./docs/development.md) for more detail on each package.

---

## Running Tests

```bash
# Run all tests
go test ./...
# or
make test

# Run tests for a specific package
go test ./internal/auth/...
go test ./internal/policy/...

# Run with verbose output
go test -v ./...

# If the Go cache is not writable in your environment
GOCACHE=/tmp/lockr-gocache go test ./...
```

**Vet and lint:**

```bash
go vet ./...
# or
make vet

# Requires golangci-lint installed
make lint
```

**Before submitting a PR, make sure:**

- `go build ./...` passes with no errors
- `go test ./...` passes with no failures
- `go vet ./...` reports no issues
- Any new behavior is covered by tests

---

## Making Changes

**Keep changes focused.** Each PR should address one thing — a bug fix, a feature, or a refactor. Do not mix unrelated changes.

**Editing handlers:** Every HTTP handler that reads from a path must call `s.policy.Allowed()` before performing the operation. See any existing handler in `internal/api/` for the pattern.

**Editing auth:** Session tokens use Argon2id hashing. Admin tokens use the same. Do not store plaintext tokens.

**Editing storage:** Secret values must be encrypted before writing to BadgerDB using `crypto.Encrypt(path, plaintext)`. The path used for encryption must be stable and unique per record.

**Updating docs:** If your change affects user-facing behavior, update the matching file in `docs/`. One file per task. Do not document planned behavior as if it already works.

**Adding a new policy capability:** Update `internal/policy/policy.go`, add tests, and document it in `docs/policies.md`.

---

## Submitting a Pull Request

1. **Create a branch** off `main`:

```bash
git checkout -b fix/my-bug-fix
```

2. **Make your changes** and commit with a clear message:

```bash
git commit -m "fix: require CapWrite for DB credential generation"
```

3. **Push and open a PR** against `main`:

```bash
git push origin fix/my-bug-fix
```

4. **In the PR description, include:**
   - What the change does and why
   - How to test it
   - Any relevant docs or issue links

We will review within a few days. We may ask for changes before merging.

---

## Commit Message Style

Use a short prefix to describe the type of change:

| Prefix | When to use |
|---|---|
| `feat:` | New feature or capability |
| `fix:` | Bug fix |
| `security:` | Security-related fix |
| `test:` | Adding or updating tests |
| `docs:` | Documentation only |
| `refactor:` | Code change with no behavior change |
| `chore:` | Build, CI, dependency updates |

Keep the first line under 72 characters. Add more detail in the body if needed.

---

## Reporting Bugs

Open a GitHub issue with:

- What you expected to happen
- What actually happened
- Steps to reproduce
- Your OS, Go version, and Lockr version or commit hash
- Any relevant logs or error output

---

## Security Issues

**Do not open a public issue for security vulnerabilities.**

See [SECURITY.md](./SECURITY.md) for responsible disclosure instructions.

---

## Questions

If you are unsure about something — whether a change is a good idea, how something works, or where to start — open a GitHub issue and ask. We are happy to discuss before you invest time in a PR.
