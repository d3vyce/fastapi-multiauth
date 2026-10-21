---
icon: lucide/key-round
---

# Bearer tokens

[`HTTPBearerAuth`][fastapi_multiauth.HTTPBearerAuth] reads `Authorization: Bearer <token>`. It is the source for API clients, scripts and service-to-service calls. For JWTs from an identity provider, see [JWT and OAuth 2.0](jwt-and-oauth2.md).

## Issuing and storing tokens

```python
--8<-- "docs_src/bearer_tokens/issue.py"
```

- `generate_token()` returns 256 random bits with the source's prefix in front.
- Store [`hash_token(token)`][fastapi_multiauth.hash_token], never the token. SHA-256 is right for random tokens; it is **not** right for passwords.
- Revoking a token is deleting its row, and it takes effect immediately.

## Prefixes

`prefix="user_"` makes the source only accept tokens starting with `user_`. Give each kind of token its own prefix and source, and combine them with [`MultiAuth`](multiauth.md): each validator only ever sees its own tokens. Prefixes also help secret scanners spot leaked tokens.

## Checksummed tokens

[`checksum_token_generator`][fastapi_multiauth.checksum_token_generator] adds a short checksum to each token, GitHub-style. The validator can then refuse a typo without a database lookup:

```python
--8<-- "docs_src/bearer_tokens/checksum.py"
```

!!! warning
    Anyone can compute the checksum. It filters typos; the hash lookup is still what authenticates.
