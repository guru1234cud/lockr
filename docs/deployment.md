# Deployment

This guide describes the current Docker Compose and production filesystem layout.

## Production Filesystem Layout

Typical paths:

```text
/etc/lockr/config.yml
/etc/lockr/policies/
/etc/lockr/tls/ca.crt
/etc/lockr/tls/server.crt
/etc/lockr/tls/server.key
/var/lib/lockr/master.key.enc
/var/lib/lockr/data/
/var/lib/lockr/audit.log
```

## Environment

Production startup requires:

```bash
LOCKR_PASSPHRASE=<passphrase>
```

This unlocks the encrypted master key.

## Docker Compose

The compose file is in:

```text
deployments/docker-compose.yml
```

It mounts:

```text
lockr_data:/var/lib/lockr
./config.yml:/etc/lockr/config.yml:ro
./policies:/etc/lockr/policies:ro
./tls:/etc/lockr/tls:ro
```

It also runs with:

- read-only container filesystem
- `/tmp` tmpfs
- all Linux capabilities dropped
- `no-new-privileges`
- healthcheck against `/v1/sys/health`

## Start With Compose

From the deployment directory, provide the passphrase:

```bash
export LOCKR_PASSPHRASE=<passphrase>
docker compose up -d
```

## Policy Updates

Because policies are mounted read-only into the container, edit policy files on the host and reload:

```bash
lockr policy reload \
  --addr https://localhost:8300 \
  --ca ./tls/ca.crt \
  --token <admin-token>
```

## Backup Targets

Back up:

```text
/var/lib/lockr/master.key.enc
/var/lib/lockr/data/
/etc/lockr/config.yml
/etc/lockr/policies/
/etc/lockr/tls/
```

The encrypted master key and passphrase are both required to recover encrypted secrets.
