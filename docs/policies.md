# Policies

Policies answer one question: what is this identity allowed to do?

Policies are stored as YAML files on the server filesystem. They are not stored in the client and not stored in BadgerDB.

## Location

The policy directory comes from config:

```yaml
policy:
  dir: "/etc/lockr/policies"
```

Every `.yaml` or `.yml` file in that directory is loaded by the server.

## Example Policy

```yaml
name: api-server
description: "Policy for the main API backend service"

rules:
  - path: "secrets/kv/prod/api/*"
    capabilities: [read]

  - path: "secrets/transit/payments-key"
    capabilities: [encrypt, decrypt]

  - path: "secrets/db/postgres/main"
    capabilities: [read]
```

The `name` field is important. Services and sessions refer to the policy by this name.

## Capabilities

Supported capabilities:

```text
read
write
delete
list
encrypt
decrypt
```

## Path Matching

Policy paths support:

- exact match: `secrets/transit/payments-key`
- one trailing wildcard: `secrets/kv/prod/api/*`

The wildcard matches the prefix and nested paths.

## Deny by Default

If no rule matches, access is denied.

This is the core rule:

```text
no matching allow = no access
```

## Explicit Deny

Use `deny: true` to block a path even when another rule might allow it:

```yaml
rules:
  - path: "secrets/kv/prod/*"
    capabilities: [read]

  - path: "secrets/kv/prod/private/*"
    deny: true
```

In the current engine, an explicit deny returns false immediately.

## Root Policy

The special policy name `root` allows everything.

It is used in dev mode and should be treated as highly privileged.

## Reload Policies

After creating or editing policy files:

```bash
lockr policy reload \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt \
  --token <admin-token>
```

or send `SIGHUP` to the server process.

## Debug Current Policy

Use:

```bash
lockr debug \
  --identity api-server \
  --key ./certs/api-server.key \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt
```

This calls `/v1/auth/whoami` and returns the identity, auth method, and active policy.

## Practical Design Advice

- Create one policy per service role.
- Give only the required capabilities.
- Avoid broad paths such as `secrets/kv/*` unless the service truly needs wide access.
- Separate read-only services from write-capable services.
- Avoid assigning `root` to application services.
