---
icon: lucide/layers
---

# Combining sources

## `MultiAuth`

[`MultiAuth`][fastapi_multiauth.MultiAuth] puts several sources on one route: browsers send a cookie, scripts send a token, both reach the same endpoints.

```python
--8<-- "docs_src/multiauth/multiauth.py"
```

Sources are tried **in order**, and the first one that finds a credential decides:

- If that credential is invalid, the request is refused. It does **not** fall through to the next source.
- With no credential at all, the 401 lists every source's challenge.
- All sources appear in `/docs`.

Put the bearer source first: when a request carries both a token and a cookie, the token the client sent on purpose wins over the cookie the browser attached on its own.

## Optional authentication

`optional()` returns a copy that gives `None` instead of a 401 when the request has **no** credential. Use it for pages that work for everyone but show more to signed-in users:

```python
--8<-- "docs_src/multiauth/optional.py"
```

A credential that is present but invalid still gets a 401: `optional()` never turns a bad token into an anonymous visitor. It works on single sources and on `MultiAuth`.

!!! warning
    `optional()` cannot be combined with [scopes](scopes.md) or [step-up](step-up.md) guards: an anonymous visitor can never satisfy them.
