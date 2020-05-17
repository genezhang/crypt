package main

import (
	"crypt/guardedclient"
	"crypt/secretcache"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"os"

	"github.com/awnumar/memguard"
)

const path string = "kv/ch-events/secrets/tenants/"

var token = os.Getenv("VAULT_TOKEN")
var vault_addr = os.Getenv("VAULT_ADDR")

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("usage: %s <id> ...\n", os.Args[0])
		return
	}
	ids := os.Args[1:]

	// Safely terminate in case of an interrupt signal
	memguard.CatchInterrupt()
	// Purge the session when we return
	defer memguard.Purge()

	gclient, err := guardedclient.NewGuardedClient(vault_addr, token)
	if err != nil {
		fmt.Println("new guarded vault client failed")
		return
	}

	secretcache := secretcache.NewSecretCache(gclient, path)

	plaintext := []byte("some plaintext, I want it to be long long long longer longer longer, very long very very long long long.")

	for _, id := range ids {
		encKeyIV, ok := secretcache.Get(id)
	  	if !ok {
			fmt.Printf("secret not found for id: %s\n", id)
			continue
		}

		// Decrypt the key from Enclave
		keyIVBuf, err := encKeyIV.Open()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		defer keyIVBuf.Destroy()

		block, err := aes.NewCipher(keyIVBuf.Bytes()[:32])
		if err != nil {
			memguard.SafePanic(err)
		}

		ciphertext := make([]byte, len(plaintext))

		stream := cipher.NewCTR(block, keyIVBuf.Bytes()[32:])
		stream.XORKeyStream(ciphertext, plaintext)

		fmt.Printf("%x\n", ciphertext)

		// CTR mode is the same for both encryption and decryption, so we can
		// also decrypt that ciphertext with NewCTR.

		plaintext2 := make([]byte, len(plaintext))
		stream = cipher.NewCTR(block, keyIVBuf.Bytes()[32:])
		stream.XORKeyStream(plaintext2, ciphertext)

		fmt.Printf("%s\n", plaintext2)
	}
}
