package guardedclient

import (
	"context"
	"encoding/hex"
	"errors"
	"net/url"

	"github.com/hashicorp/vault/api"
	"github.com/buger/jsonparser"
        "github.com/awnumar/memguard"
)

// http.Response []byte inside
type GuardedSecret  memguard.LockedBuffer

// Adding more functions related to GuardedSecret
type GuardedLogical struct {
	c *api.Client
}

//
func NewGuardedLogical(c *api.Client) *GuardedLogical {
	return &GuardedLogical{c: c}
}

func (c *GuardedLogical) Read(path string) (*GuardedSecret, error) {
	return c.ReadWithData(path, nil)
}

func (c *GuardedLogical) ReadWithData(path string, data map[string][]string) (*GuardedSecret, error) {
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

/*  definition of Secret included for reference of what's in a secret
type Secret struct {
	// The request ID that generated this response
	RequestID string `json:"request_id"`

	LeaseID       string `json:"lease_id"`
	LeaseDuration int    `json:"lease_duration"`
	Renewable     bool   `json:"renewable"`

	// Data is the actual contents of the secret. The format of the data
	// is arbitrary and up to the secret backend.
	Data map[string]interface{} `json:"data"`

	// Warnings contains any warnings related to the operation. These
	// are not issues that caused the command to fail, but that the
	// client should be aware of.
	Warnings []string `json:"warnings"`

	// Auth, if non-nil, means that there was authentication information
	// attached to this response.
	Auth *SecretAuth `json:"auth,omitempty"`

	// WrapInfo, if non-nil, means that the initial response was wrapped in the
	// cubbyhole of the given token (which has a TTL of the given number of
	// seconds)
	WrapInfo *SecretWrapInfo `json:"wrap_info,omitempty"`
}
*/

// TODO: look at secret.go, mimic the Secret interface

func (s *GuardedSecret) Bytes() []byte {
	return(*memguard.LockedBuffer)(s).Bytes()
}

// GetSecretData returns data inside Data of secret, given a key   TODO: expand to a path of more than one key
func (s *GuardedSecret) GetSecretData(key string) (*memguard.LockedBuffer, error) {
	bs, _, _, err := jsonparser.Get(s.Bytes(), "data", key)
	if err != nil {
		return nil, err
	}
	return memguard.NewBufferFromBytes(bs), nil
}

func (s *GuardedSecret) GetSecretDecodedHexBytes(key string) (*memguard.LockedBuffer, error) {
	bs, dtype, _, err := jsonparser.Get(s.Bytes(), "data", key)
	if err != nil {
		return nil, err
	}
	if dtype != jsonparser.String {
		return nil, errors.New("not a string")
	}
	buf := memguard.NewBuffer(hex.DecodedLen(len(bs)))
	l, err := hex.Decode(buf.Bytes(), bs)
	if err != nil {
		return nil, err
	}
	if l==0 {
		return nil, errors.New("empty value")
	}

	buf.Freeze()
	return buf, nil
}

