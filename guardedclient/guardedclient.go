package guardedclient

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"

	"github.com/hashicorp/vault/api"
        "github.com/awnumar/memguard"
)

// Adding more functions related to GuardedSecret
// based on Logical API
type GuardedClient struct {
	c *api.Client
}

func NewGuardedClientFromClient(client *api.Client) *GuardedClient {
	return &GuardedClient{ c: client}
}

// NewGuardedClient returns a guarded client with its vault address and token
func NewGuardedClient(vault_addr string, token string) (*GuardedClient, error) {
       config := &api.Config{
                Address: vault_addr,
        }
        client, err := api.NewClient(config)
        if err != nil {
                return nil, err
        }
        client.SetToken(token)
	return &GuardedClient{c: client}, nil
}

// Read reads a secret for a path, returning GuardedSecret as LockedBuffer
func (c *GuardedClient) Read(path string) (*GuardedSecret, error) {
	return c.ReadWithData(path, nil)
}

// ReadWithData reads a secret for a path with more data as parameters
// this function is based on the same function of the Logical
func (c *GuardedClient) ReadWithData(path string, data map[string][]string) (*GuardedSecret, error) {
	r := c.c.NewRequest("GET", "/v1/"+path)

	var values url.Values
	for k, v := range data {
		if values == nil {
			values = make(url.Values)
		}
		for _, val := range v {
			values.Add(k, val)
		}
	}

	if values != nil {
		r.Params = values
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	resp, err := c.c.RawRequestWithContext(ctx, r)    // resp is the only spot for potential exposure
	if resp != nil {
		defer resp.Body.Close()
	}
	if resp != nil && resp.StatusCode == 404 {
		secret, err := memguard.NewBufferFromEntireReader(resp.Body)
		// secret, parseErr := ParseSecret(resp.Body)
		if err != nil {
			return nil, err
		}
		if secret.Size() == 0 {
			return nil, nil
		}
		return (*GuardedSecret)(secret), nil
	}
	if err != nil {
		return nil, err
	}

	gs, err := memguard.NewBufferFromEntireReader(resp.Body)
	return (*GuardedSecret)(gs), err
}

// GenAndPutSecret generates a secret (e.g. key-iv pair) with a given length and 
// put its hex into the vault, returns the secret in LockedBuffer
func (c *GuardedClient) GenAndPutSecret(path string, size int) (*memguard.LockedBuffer, error) {
	secret, err := memguard.NewBufferFromReader(rand.Reader, size)  // e.g. 48 = 32 byte key + 16 byte IV
	if err != nil {
		return nil, err
	}
	name := []byte(`{ "keyiv": "`)
	end := []byte(`" }`)
	keyivJson := memguard.NewBuffer(len(name)+ len(end)+ hex.EncodedLen(size))
	defer keyivJson.Destroy()
	keyivJson.Move(name)
	hex.Encode(keyivJson.Bytes()[len(name):], secret.Bytes())
	keyivJson.MoveAt(len(name)+hex.EncodedLen(size), end)
	// rs is always nil here
	_, err = c.c.Logical().WriteBytes(path, keyivJson.Bytes())
	if err != nil {
		return nil, err
	}
	// fmt.Printf("secret written to Vault: path %s, kv %s return: %v\n", path, string(keyivJson.Bytes()), rs)
	return secret, nil
}

