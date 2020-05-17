package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"crypt/guardedclient"
	"github.com/awnumar/memguard"
)

const keyIVSize int = 48

var token = os.Getenv("VAULT_TOKEN")
var vault_addr = os.Getenv("VAULT_ADDR")

func main() {
	// Safely terminate in case of an interrupt signal
	memguard.CatchInterrupt()
	// Purge the session when we return
	defer memguard.Purge()

	glient, err := guardedclient.NewGuardedClient(vault_addr, token)
	if err != nil {
		return
	}

	// generate secrets for keys from 1000 to 3000 (non-inclusive)
	for i:=1000; i < 3000; i++ {
		path := fmt.Sprintf("kv/ch-events/secrets/tenant/%d", i)
		keyiv, err := glient.GenAndPutSecret(path, keyIVSize)
		if err != nil {
                        fmt.Println("error writes to Vault", err.Error())
			return
		}
		if i < 1003 {
			hexs := make([]byte, hex.EncodedLen(keyIVSize))
			hex.Encode(hexs, keyiv.Bytes())
			fmt.Printf("secret written to Vault: path %s, kv %s\n", path, string(hexs))
		} else {
			fmt.Printf(".")
		}
		keyiv.Destroy()
	}
	fmt.Println()
}

