package main

import (
	"context"
	"fmt"
	"log"

	"github.com/etherance/lockr/pkg/client"
)

func main() {
	c, err := client.New(client.Options{
		Addr:        "https://lockr:8300",
		PrivKeyPath: "./certs/api-server.key",
		CAPath:      "./certs/ca.crt",
	})
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	if err := c.Authenticate(ctx, "api-server"); err != nil {
		log.Fatal("auth failed:", err)
	}

	secret, err := c.KVGet(ctx, "secrets/prod/stripe_key", 0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("stripe key:", secret["key"])

	ct, err := c.TransitEncrypt(ctx, "payments-key", "card:4111111111111111")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("encrypted:", ct)

	pt, err := c.TransitDecrypt(ctx, "payments-key", ct)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("decrypted:", pt)
}
