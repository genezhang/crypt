package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/awnumar/memguard"
        "github.com/hashicorp/vault/api"
)

var token = os.Getenv("VAULT_TOKEN")
var vault_addr = os.Getenv("VAULT_ADDR")

func main() {
	// Safely terminate in case of an interrupt signal
	memguard.CatchInterrupt()
	// Purge the session when we return
	defer memguard.Purge()

	// get key and iv from vault
        config := &api.Config{
                Address: vault_addr,
        }
        client, err := api.NewClient(config)
        if err != nil {
                fmt.Println(err)
                return
        }
        client.SetToken(token)

	// generate secrets for keys from 1000 to 3000 (non-inclusive)
	for i:=1000; i < 3000; i++ {
		keyiv, err := memguard.NewBufferFromReader(rand.Reader, 48)    // 32 byte key + 16 byte iv
		if err != nil {
			fmt.Printf("error reading rand.Reader, bytes read: %d error: %s", keyiv.Size(), err.Error())
			return
		}
		path := fmt.Sprintf("kv/ch-events/secrets/tenant/%d", i)
		name := []byte(`{ "keyiv": "`)
		end := []byte(`" }`)
		keyivJson := memguard.NewBuffer(len(name)+ len(end)+ hex.EncodedLen(48))
		keyivJson.Move(name)
		hex.Encode(keyivJson.Bytes()[len(name):], keyiv.Bytes())
		keyivJson.MoveAt(len(name)+hex.EncodedLen(48), end)
		rs, err := client.Logical().WriteBytes(path, keyivJson.Bytes())
		if err != nil {
                        fmt.Println("error writes to Vault", err.Error())
			return
		}
		fmt.Printf("secret written to Vault: path %s, kv %s return: %v\n", path, string(keyivJson.Bytes()), rs)
		keyiv.Destroy()
		keyivJson.Destroy()
	}
}

