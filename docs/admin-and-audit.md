# Admin and Audit

Admin operations manage users, services, and admin tokens. They require an admin token.

The first admin token is created automatically by `lockr init`.

---

## User Management

Users are human operators who authenticate with a username and password.

### Create a User

```bash
lockr user create \
  --username alice \
  --policy readonly \
  --token <admin-token> \
  --ca /etc/lockr/tls/ca.crt
```

Prompts for a password. To pass it non-interactively:

```bash
lockr user create \
  --username alice \
  --policy readonly \
  --password <password> \
  --token <admin-token> \
  --ca /etc/lockr/tls/ca.crt
```

### List Users

```bash
lockr user list \
  --token <admin-token> \
  --ca /etc/lockr/tls/ca.crt
```

### Change a User's Policy

```bash
lockr user set-policy \
  --username alice \
  --policy readwrite \
  --token <admin-token> \
  --ca /etc/lockr/tls/ca.crt
```

The change takes effect on the next login. Existing sessions keep the old policy until they expire.

### Reset a Password

```bash
lockr user reset-password \
  --username alice \
  --token <admin-token> \
  --ca /etc/lockr/tls/ca.crt
```

### Delete a User

```bash
lockr user delete \
  --username alice \
  --token <admin-token> \
  --ca /etc/lockr/tls/ca.crt
```

Deleted users cannot log in. Existing sessions remain valid until they expire.

---

## Service Management

Services are applications that authenticate with Ed25519 keys.

### Enroll a Service

```bash
lockr enroll \
  --service my-app \
  --policy readwrite \
  --output ./keys/ \
  --token <admin-token> \
  --ca /etc/lockr/tls/ca.crt
```

Saves the private key to `./keys/my-app.key`. The private key is shown once.

### Revoke a Service

```bash
lockr revoke \
  --service my-app \
  --token <admin-token> \
  --ca /etc/lockr/tls/ca.crt
```

After revoke, new auth attempts by that service fail immediately.

---

## Admin Token Management

### Create an Admin

```bash
lockr admin create \
  --name ops \
  --token <existing-admin-token> \
  --ca /etc/lockr/tls/ca.crt
```

### Revoke an Admin

```bash
lockr admin revoke \
  --name ops \
  --token <admin-token> \
  --ca /etc/lockr/tls/ca.crt
```

---

## Audit Logs

Every request is logged — including login attempts, secret reads, writes, and denials.

### View Audit Log

```bash
lockr audit \
  --token <admin-token> \
  --ca /etc/lockr/tls/ca.crt
```

### Filter by Time

```bash
lockr audit --since 24h \
  --token <admin-token> \
  --ca /etc/lockr/tls/ca.crt
```

### Filter by Identity or Path

```bash
lockr audit --service user:alice --limit 50 \
  --token <admin-token> \
  --ca /etc/lockr/tls/ca.crt

lockr audit --path /v1/secrets/kv/prod \
  --token <admin-token> \
  --ca /etc/lockr/tls/ca.crt
```

### Audit Entry Fields

```text
id           — unique entry ID
timestamp    — when the request happened
identity     — who made the request (e.g. user:alice, svc:my-app, admin:root)
auth_method  — how they authenticated (password, ed25519, admin_token)
operation    — HTTP method (GET, PUT, DELETE, POST)
path         — URL path accessed
source_ip    — client IP address
request_id   — unique request ID (also in X-Request-ID response header)
status       — allowed or denied
duration_ms  — how long the request took
```

---

## Check Current Identity

```bash
lockr debug \
  --token <token> \
  --ca /etc/lockr/tls/ca.crt
```

Returns the identity, auth method, and active policy for the given token.
