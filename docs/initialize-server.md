# Initialize the Server

Use this guide for first-time production setup.

## Run Initialization

```bash
sudo lockr init --data-dir /var/lib/lockr
```

The command prompts for a passphrase that protects the master key. Choose a strong one and store it safely — it is required every time the server starts.

## What Initialization Creates

- Encrypted master key at `/var/lib/lockr/master.key.enc`
- BadgerDB data directory at `/var/lib/lockr/data/`
- TLS certificates at `/etc/lockr/tls/`
- Config file at `/etc/lockr/config.yml` (only if one does not already exist)
- Policy directory at `/etc/lockr/policies/`
- A bootstrap admin token (printed once — save it immediately)

## Example Output

```text
Master key saved to /var/lib/lockr/master.key.enc
TLS certificates generated in /etc/lockr/tls/

╔══════════════════════════════════════════════╗
║           Lockr initialized!                 ║
╚══════════════════════════════════════════════╝

Admin token (save this — shown only once):
  lkat_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

CA certificate (give this to clients):
  /etc/lockr/tls/ca.crt

Built-in policies (ready to use, no files needed):
  readonly   — read + list KV secrets
  readwrite  — read, write, delete KV + transit encrypt/decrypt
  admin      — full access to all secret engines

Start the server:
  LOCKR_PASSPHRASE='<your-passphrase>' lockr server --config /etc/lockr/config.yml
```

## Files Created

```text
/var/lib/lockr/master.key.enc
/var/lib/lockr/data/
/etc/lockr/config.yml
/etc/lockr/tls/ca.crt      (world-readable — safe to distribute to clients)
/etc/lockr/tls/ca.key      (root-only — keep private)
/etc/lockr/tls/server.crt
/etc/lockr/tls/server.key
/etc/lockr/policies/
```

## Fix Directory Permissions

After init, make the TLS directory accessible so non-root users can use the CA cert:

```bash
sudo chmod 755 /etc/lockr
sudo chmod 755 /etc/lockr/tls
```

## Master Key Behavior

The master key encrypts all secret values in BadgerDB. It is encrypted on disk and unlocked at startup using:

```bash
LOCKR_PASSPHRASE=<passphrase>
```

Both the passphrase and `master.key.enc` are required to recover secrets. Back them up to separate secure locations.

Do not commit `master.key.enc`, `ca.key`, `server.key`, or the passphrase to version control.

## TLS Behavior

The generated CA signs the server certificate. Clients verify the server using the CA certificate:

```bash
--ca /etc/lockr/tls/ca.crt
```

The `ca.crt` is public — safe to copy to client machines. The `ca.key` and `server.key` must stay private on the server.

## Next Step

See [Run the Server](./run-server.md).
