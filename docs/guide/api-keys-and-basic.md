---
icon: lucide/lock
---

# API keys and Basic

## API keys

[`APIKeyHeaderAuth`][fastapi_multiauth.APIKeyHeaderAuth] reads a named header:

```python
--8<-- "docs_src/api_keys/header.py"
```

Generate and store keys like [bearer tokens](bearer-tokens.md): random, and hashed at rest.

[`APIKeyQueryAuth`][fastapi_multiauth.APIKeyQueryAuth] is the same for a query parameter (`?api_key=...`). Prefer the header: query strings end up in logs and browser history.

## Basic auth

[`HTTPBasicAuth`][fastapi_multiauth.HTTPBasicAuth] calls your validator with `username, password`:

```python
--8<-- "docs_src/api_keys/basic.py"
```

`realm` is sent in the `WWW-Authenticate` header, which makes browsers show a login prompt. Compare secrets with `secrets.compare_digest`, never `==`, and compare bytes: it raises `TypeError` on non-ASCII strings. Check the username and the password both, so the response time does not reveal which one was wrong.
