# Authentication

Authentication answers one question: who is making the request?

Authorization is handled separately by policies.

## Auth Types

Lockr supports:

- **User auth** — username and password login for human operators.
- **Admin tokens** — long-lived tokens for system operations.
- **Ed25519 challenge-response** — key-based auth for services and applications.
- **TOTP** — time-based one-time password for services.
- **Dev mode** — bypasses all auth for local testing.

## Identity Prefixes

Every authenticated session carries an identity string. Prefixes distinguish identity types in sessions and audit logs:

```text
user:<username>    — human user logged in with password
svc:<name>         — service authenticated with Ed25519 or TOTP
admin:<name>       — admin authenticated with admin token
```

---

## User Auth

Users are human operators who log in with a username and password. An admin creates user accounts and assigns a policy to each one.

### Create a User (admin only)

```bash
lockr user create \
  --username alice \
  --policy readonly \
  --token <admin-token> \
  --ca /etc/lockr/tls/ca.crt
```

This prompts for a password. To pass it non-interactively (for scripting):

```bash
lockr user create \
  --username alice \
  --policy readonly \
  --password <password> \
  --token <admin-token> \
  --ca /etc/lockr/tls/ca.crt
```

### Login as a User

```bash
lockr login --username alice --ca /etc/lockr/tls/ca.crt
```

This prompts for a password and prints an `lvt_` session token. Use the token for subsequent requests:

```bash
export LOCKR_TOKEN=lvt_...
lockr get prod/db-password --ca /etc/lockr/tls/ca.crt
```

### Manage Users (admin only)

List users:

```bash
lockr user list --token <admin-token> --ca /etc/lockr/tls/ca.crt
```

Change a user's policy:

```bash
lockr user set-policy --username alice --policy readwrite \
  --token <admin-token> --ca /etc/lockr/tls/ca.crt
```

Reset a password:

```bash
lockr user reset-password --username alice \
  --token <admin-token> --ca /etc/lockr/tls/ca.crt
```

Delete a user:

```bash
lockr user delete --username alice \
  --token <admin-token> --ca /etc/lockr/tls/ca.crt
```

---

## Admin Tokens

Admin tokens start with `lkat_`. They are used for system operations:

- Creating and deleting users.
- Enrolling and revoking services.
- Creating more admin tokens.
- Viewing audit logs.
- Reloading policies.

The first admin token is created automatically by `lockr init` and printed once.

Create another admin:

```bash
lockr admin create --name ops \
  --token <existing-admin-token> \
  --ca /etc/lockr/tls/ca.crt
```

Revoke an admin:

```bash
lockr admin revoke --name ops \
  --token <admin-token> \
  --ca /etc/lockr/tls/ca.crt
```

---

## Ed25519 Service Auth

Ed25519 is the main auth method for services and applications. The service holds a private key; Lockr holds the matching public key.

### Enroll a Service

```bash
lockr enroll \
  --service my-app \
  --policy readwrite \
  --output ./keys/ \
  --token <admin-token> \
  --ca /etc/lockr/tls/ca.crt
```

This stores the public key in Lockr and saves the private key to `./keys/my-app.key`. The private key is shown once — keep it safe.

### Authenticate and Use

```bash
lockr get prod/db-password \
  --identity my-app \
  --key ./keys/my-app.key \
  --ca /etc/lockr/tls/ca.crt
```

The CLI handles the full challenge-response flow automatically:

```text
POST /v1/auth/challenge  →  get 32-byte random challenge
sign challenge with private key
POST /v1/auth/verify     →  verify signature → get lvt_ session token
use lvt_ token for all subsequent requests
```

### Revoke a Service

```bash
lockr revoke --service my-app \
  --token <admin-token> \
  --ca /etc/lockr/tls/ca.crt
```

After revoke, new auth attempts by that service fail immediately. The service record and its public key are deleted.

---

## Session Tokens

Session tokens start with `lvt_`. Every successful login — user, service, or admin — produces a session token.

Session metadata:

```text
identity    — who this session belongs to (e.g. user:alice, svc:my-app)
auth_method — how they authenticated (password, ed25519, admin_token)
policy      — which policy controls their access
issued_at   — when the session was created
expires_at  — when the session expires (default: 1 hour)
```

The plaintext token is never stored. Lockr stores a SHA256 lookup key and an Argon2id hash for verification.

Pass the token in requests:

```bash
# As a header
Authorization: Bearer lvt_...

# Or as an env var (CLI)
export LOCKR_TOKEN=lvt_...
```

---

## TOTP Service Auth

TOTP is an alternative auth method for services that cannot manage Ed25519 keys. Enroll with:

```bash
lockr enroll --service my-app --auth totp --policy readonly \
  --token <admin-token> --ca /etc/lockr/tls/ca.crt
```

This returns a base32 TOTP secret to load into an authenticator app or TOTP library. Login with:

```bash
POST /v1/auth/totp  { "service": "my-app", "code": 123456 }
```

---

## Dev Mode

In dev mode, every request gets:

```text
identity:    dev
auth_method: dev
policy:      root
```

Dev mode bypasses all authentication and authorization. Use it only for local testing — never in production.
