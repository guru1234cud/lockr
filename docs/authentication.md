# Authentication

Authentication answers one question: who is making the request?

Authorization is handled separately by policies.

## Auth Types

Lockr currently supports:

- Admin tokens for operators and automation.
- Ed25519 challenge-response for services.
- TOTP service login.
- Dev mode identity for local testing.

## Admin Tokens

Admin tokens start with:

```text
lkat_
```

Admin tokens are used for system operations such as:

- Creating more admins.
- Enrolling services.
- Revoking services.
- Viewing audit logs.
- Reloading policies.

Create the first admin token after production startup:

```bash
lockr admin create --name root \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt
```

The first admin can be created without an existing token only while no admin tokens exist.

Create another admin:

```bash
lockr admin create --name ops \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt \
  --token <root-admin-token>
```

Revoke an admin:

```bash
lockr admin revoke --name ops \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt \
  --token <root-admin-token>
```

## Ed25519 Service Auth

Ed25519 is the main service authentication flow.

Flow:

```text
service asks for challenge
service signs challenge with private key
server verifies signature with stored public key
server issues lvt_ session token
service uses session token for API requests
```

Enroll a service:

```bash
lockr enroll \
  --service api-server \
  --auth ed25519 \
  --policy api-server \
  --output ./certs \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt \
  --token <admin-token>
```

The server stores the service public key and policy name. The private key is returned once and saved locally.

Use the service identity and key:

```bash
lockr get prod/api/db \
  --identity api-server \
  --key ./certs/api-server.key \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt
```

## Session Tokens

Session tokens start with:

```text
lvt_
```

Session metadata includes:

- identity
- auth method
- policy name
- expiration time

The plaintext session token is not stored. Lockr stores a lookup key and verification hash.

## TOTP Service Auth

TOTP support exists for services that cannot use Ed25519. TOTP service records are stored under:

```text
auth/services/totp/<name>
```

## Dev Mode

In dev mode, requests get:

```text
identity: dev
auth_method: dev
policy: root
```

That means dev mode bypasses normal authentication and authorization. Do not use it in production.
