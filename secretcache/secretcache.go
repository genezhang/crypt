package secretcache

import (
        "fmt"
	"crypt/guardedclient"
	"sync"

        "github.com/awnumar/memguard"
)

const KeyIVSize int = 48

type SecretCache struct {
	parentPath string
	mutex  sync.Mutex
	secretCache  map[string]*memguard.Enclave
	gClient	 *guardedclient.GuardedClient
}

func NewSecretCache (glient *guardedclient.GuardedClient, path string) *SecretCache {
	return &SecretCache {
		parentPath: path,
		secretCache: map[string]*memguard.Enclave{},
		gClient: glient,
	}
}

// Get gets the secret key-iv as Enclave from the cache
// if not found, get it from the Vault
// if not exists in the Vault, generate a new secret for it
//   and store in the cache
func (sc *SecretCache) Get(key string) (*memguard.Enclave, bool) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	secret, ok := sc.secretCache[key]
	if ok {
		return secret, ok
	}
	// get secret from vault
        gsecret, err := sc.gClient.Read(sc.parentPath + key)
        if err != nil {
                fmt.Println(err)
                return nil, false
        }
        // fmt.Printf("%v\n", string(gsecret.Bytes()))

        keyiv, err := gsecret.GetSecretDecodedHexBytes("keyiv")
	if err != nil {
		fmt.Println("secret not found for", key, "generate a new secret...")
		keyiv, err = sc.gClient.GenAndPutSecret(sc.parentPath + key, KeyIVSize)
		if err != nil {
			fmt.Println("couldn't register new secret")
			return nil, false
		}
	}

        // Secure the key inside an Enclave
        encKeyIV := keyiv.Seal()
	sc.secretCache[key] = encKeyIV

	return encKeyIV, true
}

// Purge removes the entry in the cache
func (sc *SecretCache) Purge(key string) {
	_, ok := sc.secretCache[key]
	if ok {
		delete(sc.secretCache, key)
		// secret.Destroy()   Enclave does not have a destroy method
	}
}

// PurgeAll empties the cache
func (sc *SecretCache) DestroyAll() {
	sc.secretCache = map[string]*memguard.Enclave{}
}
