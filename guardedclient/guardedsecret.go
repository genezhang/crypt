package guardedclient

import (
	"encoding/hex"
	"errors"

	"github.com/awnumar/memguard"
	"github.com/buger/jsonparser"
)

// http.Response []byte inside
type GuardedSecret  memguard.LockedBuffer

// Bytes returns []byte in GuardedSecret (LockedBuffer type cast)
func (s *GuardedSecret) Bytes() []byte {
        return(*memguard.LockedBuffer)(s).Bytes()
}

// GetSecretData returns data inside "data" of secret, given a key   TODO: expand to a path of more than one key
func (s *GuardedSecret) GetSecretData(key string) (*memguard.LockedBuffer, error) {
        bs, _, _, err := jsonparser.Get(s.Bytes(), "data", key)
        if err != nil {
                return nil, err
        }
        return memguard.NewBufferFromBytes(bs), nil
}

// GetSecretDecodedHexBytes returns hex-decoded binary bytes for the key inside secret
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

// TODO: look at secret.go, mimic the Secret interface

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
