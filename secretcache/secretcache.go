package secretcache

import (
        "fmt"
	"crypto/rand"
	"encoding/hex"
	"crypt/guardedclient"

        "github.com/awnumar/memguard"
        "github.com/hashicorp/vault/api"

)

var guardedLogical *guardedclient.GuardedLogical
var client *api.Client

func InitClient(vault_addr string, token string) error {
        config := &api.Config{
                Address: vault_addr,
        }
	var err error
        client, err = api.NewClient(config)
        if err != nil {
                fmt.Println(err)
                return err
        }
        client.SetToken(token)
	guardedLogical = guardedclient.NewGuardedLogical(client)
	return nil
}

var SecretCache = map[string]*memguard.Enclave{}

// Get gets the secret key-iv as Enclave from the cache
// if not found, get it from the Vault
// if not exists in the Vault, generate a new secret for it
//   and store in the cache
func Get(key string) (*memguard.Enclave, bool) {
	secret, ok := SecretCache[key]
	if ok {
		return secret, ok
	}
	// get key and iv from vault
        gsecret, err := guardedLogical.Read("kv/ch-events/secrets/tenant/"+key)
        if err != nil {
                fmt.Println(err)
                return nil, false
        }
        // fmt.Printf("%v\n", string(gsecret.Bytes()))

        // Load your secret key from a safe place and reuse it across multiple
        // NewCipher calls. We are combining key and iv together
        keyiv, err := gsecret.GetSecretDecodedHexBytes("keyiv")
	if err != nil {
		fmt.Println("secret not found for", key, "generate a new secret...")
		keyiv, err = genSecret(key)
		if err != nil {
			fmt.Println("couldn't register new secret")
			return nil, false
		}
	}
	defer keyiv.Destroy()

        // Secure the key inside an Enclave
        // encKey := memguard.NewEnclave(key)
        encKeyIV := keyiv.Seal()
	SecretCache[key] = encKeyIV

	return encKeyIV, true
}


func genSecret(id string) (*memguard.LockedBuffer, error) {
	keyiv, err := memguard.NewBufferFromReader(rand.Reader, 48)    // 32 byte key + 16 byte iv
        if err != nil {
		fmt.Printf("error reading rand.Reader, bytes read: %d error: %s", keyiv.Size(), err.Error())
                return nil, err
        }
        path := "kv/ch-events/secrets/tenant/" + id
        name := []byte(`{ "keyiv": "`)
        end := []byte(`" }`)
        keyivJson := memguard.NewBuffer(len(name)+ len(end)+ hex.EncodedLen(48))
        keyivJson.Move(name)
        hex.Encode(keyivJson.Bytes()[len(name):], keyiv.Bytes())
        keyivJson.MoveAt(len(name)+hex.EncodedLen(48), end)
        defer keyivJson.Destroy()
        rs, err := client.Logical().WriteBytes(path, keyivJson.Bytes())
        if err != nil {
                fmt.Println("error writes to Vault", err.Error())
                return nil, err
        }
        fmt.Printf("secret written to Vault: path %s, kv %s return: %v\n", path, string(keyivJson.Bytes()), rs)
	return keyiv, nil
}

func Destroy(key string) {
	_, ok := SecretCache[key]
	if ok {
		delete(SecretCache, key)
		// secret.Destroy()   Enclave does not have a destroy method
	}
}

func DestroyAll() {
	for key, _ := range SecretCache {
		delete(SecretCache, key)
		// secret.Destroy()   Enclave does not have a destroy method
	}
}
