# API Reference

Route-level overview of the Lockr HTTP API.

Responses are JSON envelopes:

```json
{ "data": { ... }, "error": null, "request_id": "..." }
```

Errors set `"error"` to a string and `"data"` to null.

---

## Public Routes

No authentication required.

```text
GET  /v1/sys/health
POST /v1/auth/login
POST /v1/auth/challenge
POST /v1/auth/verify
POST /v1/auth/totp
POST /v1/auth/admin/login
```

---

## Authenticated Routes

All other routes require a token passed as:

```text
Authorization: Bearer <token>
X-Lockr-Token: <token>
```

Tokens are either session tokens (`lvt_...`) or admin tokens (`lkat_...`).

---

## Auth Routes

```text
POST   /v1/auth/login              User login (username + password → lvt_ token)
POST   /v1/auth/challenge          Request Ed25519 challenge for a service
POST   /v1/auth/verify             Submit signed challenge → lvt_ token
POST   /v1/auth/totp               TOTP login → lvt_ token
POST   /v1/auth/admin/login        Admin token login → lvt_ session
DELETE /v1/auth/session            Logout (revoke current session)
GET    /v1/auth/whoami             Return current identity, auth method, and policy
```

### POST /v1/auth/login

```json
{ "username": "alice", "password": "..." }
```

Response:

```json
{
  "token": "lvt_...",
  "identity": "user:alice",
  "policy": "readonly",
  "expires_in": 3600
}
```

---

## User Management Routes

Admin token required.

```text
POST   /v1/sys/users                    Create a user
GET    /v1/sys/users                    List users
DELETE /v1/sys/users/<username>         Delete a user
PUT    /v1/sys/users/<username>/policy  Change a user's policy
PUT    /v1/sys/users/<username>/password  Reset a user's password
```

### POST /v1/sys/users

```json
{ "username": "alice", "password": "...", "policy": "readonly" }
```

### PUT /v1/sys/users/alice/policy

```json
{ "policy": "readwrite" }
```

### PUT /v1/sys/users/alice/password

```json
{ "password": "new-password" }
```

---

## KV Routes

```text
GET    /v1/secrets/kv/<path>       Read a secret (latest or ?version=N)
PUT    /v1/secrets/kv/<path>       Write a secret
DELETE /v1/secrets/kv/<path>       Delete a secret
GET    /v1/secrets/kv/<path>/      List secrets at path prefix
```

Policy checks:

```text
GET    → read
GET /  → list
PUT    → write
DELETE → delete
```

Policy path format: `secrets/kv/<path>`

---

## Transit Routes

```text
POST /v1/secrets/transit/<keyname>/create   Create a transit key (admin only)
POST /v1/secrets/transit/<keyname>/encrypt  Encrypt data
POST /v1/secrets/transit/<keyname>/decrypt  Decrypt data
POST /v1/secrets/transit/<keyname>/rotate   Rotate the key
POST /v1/secrets/transit/<keyname>/info     Get key info
```

Policy checks:

```text
create  → write  (admin token required)
encrypt → encrypt
decrypt → decrypt
rotate  → write  (admin token required)
info    → read
```

Policy path format: `secrets/transit/<keyname>`

---

## Dynamic DB Routes

```text
GET    /v1/secrets/db/<name>/config         Get DB role config
PUT    /v1/secrets/db/<name>/config         Set DB role config (admin only)
POST   /v1/secrets/db/<name>/creds          Generate credentials
GET    /v1/secrets/db/<name>/creds          List active leases
DELETE /v1/secrets/db/<name>/creds/<id>     Revoke a lease
POST   /v1/secrets/db/<name>/test           Test the DB connection
```

Policy checks:

```text
GET config    → read   (admin token required)
PUT config    → write  (admin token required)
POST creds    → write
GET creds     → list
DELETE creds  → delete
POST test     → read   (admin token required)
```

Policy path format: `secrets/db/<name>`

---

## System / Admin Routes

Admin token required.

```text
GET    /v1/sys/health               Health check (public)
GET    /v1/sys/status               Server status and runtime info
POST   /v1/sys/enroll               Enroll a service (Ed25519 or TOTP)
DELETE /v1/sys/revoke/<service>     Revoke a service
GET    /v1/sys/audit                Query audit log
POST   /v1/sys/admin/create         Create an admin token
DELETE /v1/sys/admin/<name>         Delete an admin token
POST   /v1/sys/policy/reload        Reload policy files from disk
```

---

## Request IDs

Every request gets an `X-Request-ID` response header. The same ID appears in the audit log entry for that request.
