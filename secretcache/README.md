# Secret Cache

Keeps a cache of secrets (key-iv pairs) (a map of id to its secret in Enclave)

If a secret is not in the cache, it will try to fetch it from the Vault.
If it's not found in the Vault, it will generate one for the id, and store in the Vault.
The fetched secret or generated one will be cached in the map.
