# Go Vault Secret for Encryption

Just started to connect Hashicorp Vault to memguard to keep key/iv safe.
Use to encrypt and decrypt data. The key-iv pair used for encryption are stored in the Vault.

* Added `guardedclient` based on vault/api with only potential exposure is the http.Response.
* The secret byte slice is immediately put into a `LockedBuffer` reading from `resp.Body` (`GuardedSecret`).
* The secret byte slice is decoded not using JSON decoder but using no-copy scan for JSON path to
return values using `buger/jsonparser`.
* A returned value is in a `LockedBuffer` that can be sealed into an `Enclave`.
* Added `secretcache`, a map used to keep the secrets in a local cache.

TODO: more functions on `GuardedSecret`.

## Start Vault docker in dev mode

```
docker run --cap-add=IPC_LOCK -e 'VAULT_DEV_ROOT_TOKEN_ID=myroot' -d -p 8200:8200 --name=vault vault
docker exec -it vault /bin/sh
```

Once you are inside the container, execute the following:
```
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN=myroot
vault secrets enable kv
vault kv put kv/ch-events/secrets/tenant key=6368616e676520746869732070617373776f726420746f206120736563726574 iv=8b64a9433eae7ccceee2fc0eda267d5a
```
The key and iv pair are just for testing purpose.

 
## To run Go code outside of the container

Need to setup the same environment variables:
```
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN=myroot
```

To generate a set of secrets for ids from 1000 to 3000:
```
go run gensecrets.go
```

Then execute:
```
go run main.go 1000 1002 2000 1002 4000
```
This includes testing for secret cache and generate a secret on demand.

