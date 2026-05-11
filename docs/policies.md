# Policies

Policies answer one question: what is this identity allowed to do?

Policies are assigned to users and services. They define which secret paths can be accessed and with which capabilities.

---

## Built-in Policies

Lockr ships three built-in policies that work without any files:

| Policy | Capabilities |
|---|---|
| `readonly` | read, list on `secrets/kv/*` |
| `readwrite` | read, write, delete, list on `secrets/kv/*` + encrypt, decrypt on `secrets/transit/*` |
| `admin` | full access to KV, transit, and DB secret engines |

Use them directly when creating users or enrolling services:

```bash
lockr user create --username alice --policy readonly ...
lockr enroll --service my-app --policy readwrite ...
```

No policy files needed for these.

---

## Custom Policy Files

When built-in policies are not specific enough, write a YAML policy file.

### Location

```yaml
policy:
  dir: "/etc/lockr/policies"
```

Every `.yaml` or `.yml` file in that directory is loaded at startup.

### Example

```yaml
name: api-backend
description: "Policy for the main API service"

rules:
  - path: "secrets/kv/prod/api/*"
    capabilities: [read]

  - path: "secrets/transit/payments-key"
    capabilities: [encrypt, decrypt]

  - path: "secrets/db/postgres-main"
    capabilities: [read]
```

The `name` field is what you pass to `--policy` when creating users or enrolling services.

### Capabilities

```text
read     — read a secret value
write    — create or update a secret
delete   — soft-delete a secret
list     — list secrets at a path prefix
encrypt  — encrypt data with a transit key
decrypt  — decrypt data with a transit key
```

### Path Matching

- Exact match: `secrets/transit/payments-key`
- Trailing wildcard: `secrets/kv/prod/api/*`

The wildcard matches the prefix and all paths beneath it.

### Deny by Default

If no rule matches a request, access is denied. There is no implicit allow.

### Explicit Deny

Use `deny: true` to block a specific path even when a broader rule would allow it:

```yaml
rules:
  - path: "secrets/kv/prod/*"
    capabilities: [read]

  - path: "secrets/kv/prod/internal/*"
    deny: true
```

An explicit deny returns false immediately — it overrides any allow rule.

---

## Override a Built-in Policy

Create a YAML file with the same name as the built-in to override it:

```yaml
name: readonly
description: "Custom readonly — only prod KV"

rules:
  - path: "secrets/kv/prod/*"
    capabilities: [read, list]
```

File-loaded policies take priority over built-ins.

---

## Root Policy

The special policy name `root` grants all capabilities on all paths. It is used in dev mode and should never be assigned to application users or services.

---

## Reload Policies

After creating or editing policy files, reload without restarting:

```bash
lockr policy reload \
  --token <admin-token> \
  --ca /etc/lockr/tls/ca.crt
```

Or send `SIGHUP` to the server process:

```bash
sudo kill -HUP <server-pid>
```

---

## Practical Design Advice

- Assign `readonly` to services that only fetch secrets.
- Assign `readwrite` to services that store or rotate secrets.
- Write custom policies when you need to restrict access to specific paths.
- Never assign `root` or `admin` to application services.
- Create one policy per role — multiple users and services can share the same policy name.
