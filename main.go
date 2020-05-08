package main

import (
	"crypt/guardedclient"
	"crypto/aes"
	"crypto/cipher"
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
        gsecret, err := guardedclient.NewGuardedLogical(client).Read("kv/ch-events/secrets/tenant")
        if err != nil {
                fmt.Println(err)
                return
        }
	// fmt.Printf("%v\n", string(gsecret.Bytes()))

	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls.
	key, _ := gsecret.GetSecretDecodedHexBytes("key")
	// We will make the IV secure also
	iv, _ := gsecret.GetSecretDecodedHexBytes("iv")

	// Secure the key inside an Enclave
	// encKey := memguard.NewEnclave(key)
	encKey := key.Seal()
	// Secure the iv inside an Enclave
	// encIV := memguard.NewEnclave(iv)
	encIV := iv.Seal()

	plaintext := []byte("some plaintext, I want it to be long long long longer longer longer, very long very very long long long.")

	// Decrypt the key from Enclave
	keyBuf, err := encKey.Open()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	defer keyBuf.Destroy()

	block, err := aes.NewCipher(keyBuf.Bytes())
	if err != nil {
		memguard.SafePanic(err)
	}

	ivBuf, err := encIV.Open()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	defer ivBuf.Destroy()

	ciphertext := make([]byte, len(plaintext))

	stream := cipher.NewCTR(block, ivBuf.Bytes())
	stream.XORKeyStream(ciphertext, plaintext)

	fmt.Printf("%x\n", ciphertext)

	// CTR mode is the same for both encryption and decryption, so we can
	// also decrypt that ciphertext with NewCTR.

	plaintext2 := make([]byte, len(plaintext))
	stream = cipher.NewCTR(block, ivBuf.Bytes())
	stream.XORKeyStream(plaintext2, ciphertext)

	fmt.Printf("%s\n", plaintext2)
}
