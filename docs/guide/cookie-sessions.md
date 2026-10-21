---
icon: lucide/cookie
---

# Cookie sessions

[`APIKeyCookieAuth`][fastapi_multiauth.APIKeyCookieAuth] reads a cookie. With a `secret_key`, the cookie is **signed and expires on its own**: a session without a session table.

```python
--8<-- "docs_src/cookie_sessions/login.py"
```

`set_cookie` signs the value and adds a timestamp. Each request checks the signature and age before your validator runs, so it only sees the value you set. (Store password hashes in a real app; the dict here is a stand-in.)

## Options

| Argument | Default | |
| --- | --- | --- |
| `secret_key` | `None` | At least 32 bytes. Without it the cookie is **not signed**. |
| `ttl` | `86400` | Lifetime in seconds. |
| `secure` | `True` | Turn off only for local HTTP development. |
| `samesite` | `"lax"` | `"strict"` or `"none"`. |
| `session_id` | `False` | See [revocable sessions](#revocable-sessions). |

!!! info "Signed is not encrypted"
    Anyone holding the cookie can read its value. Store an id in it, never a secret.

!!! tip "Name the cookie `__Host-...`"
    A `__Host-` cookie cannot be overwritten from a subdomain. The defaults already satisfy its rules.

## CSRF

Browsers send cookies with every request to your site, whoever triggered it. `samesite="lax"` blocks most cross-site requests but not all of them. Protect cookie-authenticated `POST`, `PUT`, `PATCH` and `DELETE` routes with a CSRF token or an `Origin` check, or use `samesite="strict"`.

## Key rotation

Pass a list of keys: the first one signs, all of them verify. Add the new key in front, then remove the old one once a `ttl` has passed.

## Revocable sessions

A signed cookie stays valid until it expires; `delete_cookie` only clears one browser. To end a session for real, set `session_id=True`: each `set_cookie` creates a random id, returns it, and passes it to your validator.

```python
--8<-- "docs_src/cookie_sessions/revocable.py"
```

You decide where the ids live and what "revoked" means. `session_id_of(request)` returns the current id; the [Sign out everywhere](../recipes/sign-out-everywhere.md) recipe builds a device list with it.
