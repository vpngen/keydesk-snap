package main

import (
	"flag"
	"log"
	"os"

	"github.com/vpngen/keydesk-snap/core/crypto"
)

func main() {
	decrypt := flag.Bool("d", false, "decrypt")
	encrypt := flag.Bool("e", false, "encrypt")

	flag.Parse()

	secret := os.Getenv("SECRET")
	if secret == "" {
		log.Fatalf("SECRET is empty")
	}

	if *decrypt == *encrypt {
		log.Fatalf("either -d or -e must be set")
	}

	if *decrypt {
		if err := crypto.DecryptAES256CBC(os.Stdin, os.Stdout, []byte(secret)); err != nil {
			log.Fatalf("decrypt: %s", err)
		}
	}

	if *encrypt {
		if err := crypto.EncryptAES256CBC(os.Stdin, os.Stdout, []byte(secret)); err != nil {
			log.Fatalf("encrypt: %s", err)
		}
	}
}
