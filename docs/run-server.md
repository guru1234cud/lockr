# Run the Server

Use this guide when starting Lockr locally or in production mode.

---

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
- In-memory storage (data is lost on restart).
- Every request gets the `root` policy.

Use dev mode only for local testing.

---

## Production Mode

### 1. Initialize (once)

```bash
sudo lockr init --data-dir /var/lib/lockr
```

Save the admin token printed during init. Fix directory permissions so non-root users can read the CA cert:

```bash
sudo chmod 755 /etc/lockr
sudo chmod 755 /etc/lockr/tls
```

### 2. Start the Server

```bash
LOCKR_PASSPHRASE='<your-passphrase>' sudo lockr server --config /etc/lockr/config.yml
```

### 3. Create Users and Services

```bash
# Create a user
lockr user create --username alice --policy readonly \
  --token <admin-token> --ca /etc/lockr/tls/ca.crt

# Enroll a service
lockr enroll --service my-app --policy readwrite \
  --token <admin-token> --ca /etc/lockr/tls/ca.crt
```

---

## Health Check

```bash
curl --cacert /etc/lockr/tls/ca.crt https://localhost:8300/v1/sys/health
```

With the CLI:

```bash
lockr status --addr https://localhost:8300 --ca /etc/lockr/tls/ca.crt
```

---

## Reload Policies

Policies are loaded at startup. To reload without restarting:

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

## Run the E2E Test Suite

After the server is running, verify all features work end-to-end:

```bash
export LOCKR_TOKEN=<admin-token>
export LOCKR_CA=/etc/lockr/tls/ca.crt
./test/e2e.sh
```

The suite tests user login, service auth, permission enforcement, policy changes, password reset, and audit logging. All test data uses an `e2e-` prefix and is cleaned up automatically.
