package main

import (
	"crypt/guardedclient"
	"crypt/secretcache"
	"crypto/aes"
	"crypto/cipher"
//	"encoding/binary"
	"fmt"
//	"math"
	"os"
	"unsafe"

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

		// encrypt a float32 number
		var f float32 = 123.456
		ci := make([]byte, 4)
	        stream = cipher.NewCTR(block, keyIVBuf.Bytes()[32:])
		fb := (*[4]byte)(unsafe.Pointer(&f))[:]
		stream.XORKeyStream(ci, fb)
		// stream.XORKeyStream(ci, (*[4]byte)(unsafe.Pointer(&f))[:])
		fmt.Printf("%x\n", ci)
		/*
		bits := binary.LittleEndian.Uint32(ci)
		float := math.Float32frombits(bits)
		fmt.Printf("encypted: %g\n", f)
		*/
		float := **(**float32)(unsafe.Pointer(&ci))
		fmt.Printf("encypted: %g\n", float)

	        stream = cipher.NewCTR(block, keyIVBuf.Bytes()[32:])
		stream.XORKeyStream(fb, ci)
		/* stream.XORKeyStream(ci, ci)
		bits = binary.LittleEndian.Uint32(ci)
		float = math.Float32frombits(bits)
		*/
		fmt.Printf("decypted: %g\n", f)
	}
}
