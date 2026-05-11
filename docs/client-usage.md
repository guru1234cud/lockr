# Client Usage

Lockr can be used through:

- The `lockr` CLI.
- The Go SDK in `pkg/client`.
- Example clients in `examples/`.

---

## CLI Global Flags

```text
--addr      Server address (default: https://localhost:8300)
--ca        Path to CA certificate
--token     Session or admin token
--identity  Service name for Ed25519 auth
--key       Path to service Ed25519 private key
--output    Output format: text or json
```

Environment variable equivalents:

```text
LOCKR_ADDR
LOCKR_CA
LOCKR_TOKEN
LOCKR_SERVICE
LOCKR_KEY
```

---

## User Login

Users authenticate with username and password and receive a session token:

```bash
lockr login --username alice --ca /etc/lockr/tls/ca.crt
# prompts for password → prints lvt_ token
```

Non-interactive (for scripts):

```bash
lockr login --username alice --password <password> --ca /etc/lockr/tls/ca.crt
```

Export the token for subsequent commands:

```bash
export LOCKR_TOKEN=lvt_...
lockr get prod/db-password --ca /etc/lockr/tls/ca.crt
```

---

## Service CLI Usage

Services authenticate with Ed25519 keys:

```bash
lockr get prod/api/db \
  --identity my-app \
  --key ./keys/my-app.key \
  --ca /etc/lockr/tls/ca.crt
```

The CLI handles the challenge-response flow automatically. A session token is obtained and used for the request.

---

## Admin CLI Usage

Admin operations use `--token` with an `lkat_` admin token:

```bash
lockr user create --username alice --policy readonly \
  --token <admin-token> --ca /etc/lockr/tls/ca.crt

lockr enroll --service my-app --policy readwrite \
  --token <admin-token> --ca /etc/lockr/tls/ca.crt

lockr audit --since 24h \
  --token <admin-token> --ca /etc/lockr/tls/ca.crt
```

---

## JSON Output

```bash
lockr get prod/api/db --output json \
  --identity my-app \
  --key ./keys/my-app.key \
  --ca /etc/lockr/tls/ca.crt
```

---

## Go SDK

```go
package main

import (
	"context"
	"fmt"

	lockr "github.com/etherance/lockr/pkg/client"
)

func main() {
	ctx := context.Background()

	c, err := lockr.New(lockr.Options{
		Addr:        "https://localhost:8300",
		PrivKeyPath: "./keys/my-app.key",
		CAPath:      "/etc/lockr/tls/ca.crt",
	})
	if err != nil {
		panic(err)
	}

	if err := c.Authenticate(ctx, "my-app"); err != nil {
		panic(err)
	}

	secret, err := c.KVGet(ctx, "prod/api/db", 0)
	if err != nil {
		panic(err)
	}

	fmt.Println(secret)
}
```

See `examples/go/main.go`, `examples/nodejs/lockr_example.js`, and `examples/python/lockr_example.py` for more.

---

## TLS Note

`--ca` is required when connecting to an HTTPS server. Without it, the CLI exits with an error rather than falling back to an insecure connection. Set `LOCKR_CA` to avoid passing it on every command:

```bash
export LOCKR_CA=/etc/lockr/tls/ca.crt
```

Dev mode uses plain HTTP so `--ca` is not needed.
