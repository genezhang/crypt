# Go Vault Secret for Encryption

Just started to connect Hashicorp Vault to memguard to keep key/iv safe.
Use to encrypt and decrypt data.

* Added `guardedclient` based on vault/api with only potential exposure is the http.Response.
* The secret byte slice is immediately put into a `LockedBuffer` reading from `resp.Body` (`GuardedSecret`).
* The secret byte slice is not decoded using JSON decode by using no-copy scan for JSON path to
return values using `buger/jsonparser`.
* A returned value is in a `LockedBuffer` that can be sealed into an `Enclave`.

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

Then execute:
```
go run main.go
```
