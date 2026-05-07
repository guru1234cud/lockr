# Run the Server

Use this guide when starting Lockr locally or in production mode.

## Dev Mode

Build the binary:

```bash
go build -o lockr ./cmd/lockr
```

Start the server:

```bash
./lockr server --dev
```

Dev mode listens on:

```text
http://localhost:8300
```

Dev mode behavior:

- No TLS.
- No authentication enforcement.
- In-memory storage.
- Every request gets the `root` policy.

Use dev mode only for local testing.

## Production Mode

Initialize once:

```bash
lockr init --data-dir /var/lib/lockr
```

Start the server:

```bash
LOCKR_PASSPHRASE=<passphrase> lockr server --config /etc/lockr/config.yml
```

Production mode uses HTTPS and persistent BadgerDB storage.

## Health Check

```bash
curl -k https://localhost:8300/v1/sys/health
```

With the CLI:

```bash
lockr status \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt
```

## Reload Policies

Policies are loaded at startup. To reload without restarting:

```bash
lockr policy reload \
  --addr https://localhost:8300 \
  --ca /etc/lockr/tls/ca.crt \
  --token <admin-token>
```

You can also send `SIGHUP` to the server process.
