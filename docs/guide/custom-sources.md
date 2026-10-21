---
icon: lucide/puzzle
---

# Custom sources

When no built-in source reads your credential, subclass [`AuthSource`][fastapi_multiauth.AuthSource] and write two methods:

```python
--8<-- "docs_src/custom_sources/client_cert.py"
```

`extract(request)`
:   Find the credential in the request. Return `None` when it is absent, so `MultiAuth` and `optional()` work.

`authenticate(credential)`
:   Return the user or raise, like a [validator](validators.md).

`X-Client-Cert` comes from the proxy that terminates TLS, so `extract()` ignores it on connections from anywhere else. The proxy must overwrite any value the client sent. If uvicorn trusts the proxy through `--forwarded-allow-ips`, `request.client` is the original client's address instead, and this check refuses every request.

The scheme passed to `super().__init__()` is only used for OpenAPI. Your source works with `MultiAuth`, `optional()`, WebSockets, logging and auditing like the built-in ones.

To check [scopes](scopes.md) or use [`fresh()`](step-up.md), override `authenticate_scoped()` and `authenticated_at()`. See the [API reference](../reference.md#fastapi_multiauth.AuthSource).
