# API Reference

This is a route-level overview of the current HTTP API.

Responses are JSON objects. Errors use an `error` field.

## Public Routes

```text
GET  /v1/sys/health
POST /v1/auth/challenge
POST /v1/auth/verify
POST /v1/auth/totp
POST /v1/auth/admin/login
```

Public means the route is not wrapped by the normal auth middleware.

## Authenticated Routes

Authenticated routes accept either:

- `Authorization: Bearer <token>`
- `X-Lockr-Token: <token>`

Tokens can be session tokens (`lvt_...`) or admin tokens (`lkat_...`) depending on the route.

## Auth Routes

```text
DELETE /v1/auth/session
GET    /v1/auth/whoami
```

## KV Routes

```text
GET    /v1/secrets/kv/<path>
PUT    /v1/secrets/kv/<path>
DELETE /v1/secrets/kv/<path>
GET    /v1/secrets/kv/<path>/
GET    /v1/secrets/kv/<path>/versions
```

Policy checks:

```text
GET secret      -> read
GET versions    -> read
GET directory   -> list
PUT secret      -> write
DELETE secret   -> delete
```

Policy path format:

```text
secrets/kv/<path>
```

## Transit Routes

```text
POST /v1/secrets/transit/<keyname>/create
POST /v1/secrets/transit/<keyname>/encrypt
POST /v1/secrets/transit/<keyname>/decrypt
POST /v1/secrets/transit/<keyname>/rotate
POST /v1/secrets/transit/<keyname>/info
```

Policy checks:

```text
encrypt -> encrypt
decrypt -> decrypt
```

Current gap: create, rotate, and info do not yet enforce policy checks.

Policy path format:

```text
secrets/transit/<keyname>
```

## Dynamic DB Routes

```text
GET    /v1/secrets/db/<name>/config
PUT    /v1/secrets/db/<name>/config
POST   /v1/secrets/db/<name>/creds
GET    /v1/secrets/db/<name>/creds
DELETE /v1/secrets/db/<name>/creds/<lease-id>
POST   /v1/secrets/db/<name>/test
```

Policy checks:

```text
GET config    -> read
PUT config    -> write
POST creds    -> read
```

Current gap: list leases, revoke lease, and test config do not yet enforce policy checks.

Policy path format:

```text
secrets/db/<name>
```

## Admin Routes

```text
GET    /v1/sys/status
POST   /v1/sys/enroll
DELETE /v1/sys/revoke/<service>
GET    /v1/sys/audit
POST   /v1/sys/admin/create
DELETE /v1/sys/admin/<name>
POST   /v1/sys/policy/reload
```

These routes require admin-token authentication outside dev mode.

## Request IDs

Every request receives an `X-Request-ID` response header. The same request ID is written into audit entries.
