---
icon: lucide/cookie
---

# Cookie sessions

[`APIKeyCookieAuth`][fastapi_multiauth.APIKeyCookieAuth] reads a cookie. With a `secret_key`, the cookie is **signed and expires on its own**: a session without a session table.

```python
--8<-- "docs_src/cookie_sessions/login.py"
```

`set_cookie` signs the value and adds a timestamp. Each request checks the signature and age before your validator runs, so it only sees the value you set.

Passwords are stored as salted scrypt hashes and compared with `hmac.compare_digest`. An unknown username is checked against `NO_PASSWORD`, so it takes as long to refuse as a wrong password.

`delete_cookie` removes the cookie from the browser, but a copy of it stays valid until `ttl` runs out. To end a session on the server, use [revocable sessions](#revocable-sessions).

## Options

| Argument | Default | |
| --- | --- | --- |
| `secret_key` | `None` | At least 32 bytes. Without it the cookie is **not signed**. |
| `ttl` | `86400` | Lifetime in seconds. |
| `secure` | `True` | Turn off only for local HTTP development. |
| `samesite` | `"lax"` | `"strict"` or `"none"`. |
| `session_id` | `False` | See [revocable sessions](#revocable-sessions). |
| `csrf` | `False` | Refuse requests from other origins. See [CSRF](#csrf). |
| `trusted_origins` | `()` | Other origins `csrf` lets through. |

!!! info "Signed is not encrypted"
    Anyone holding the cookie can read its value. Store an id in it, never a secret.

!!! tip "Name the cookie `__Host-...`"
    A `__Host-` cookie cannot be overwritten from a subdomain. The defaults already satisfy its rules.

## CSRF

Browsers send cookies with every request to your site, whoever triggered it. `samesite="lax"` blocks most cross-site requests but not all of them. Set `csrf=True` to refuse the rest:

```python
--8<-- "docs_src/cookie_sessions/csrf.py"
```

Every request except `GET`, `HEAD` and `OPTIONS` must now come from your own origin, or from one listed in `trusted_origins`, such as a frontend on its own domain. Anything else gets a **403** before your validator runs. A sibling subdomain counts as another origin.

The check reads `Sec-Fetch-Site`, which browsers set and pages cannot forge, and falls back to comparing `Origin` with the `Host` header for older browsers. Behind a proxy, keep the `Host` header intact or list your public origin in `trusted_origins`.

!!! warning "Scripts and tests"
    A request carrying neither header is refused too. Every browser released since 2020 sends one, so only non-browser clients are affected: send `Sec-Fetch-Site: same-origin` from your tests, and give scripts a bearer token instead of a cookie.

`GET` routes are never checked, so keep them free of side effects.

## Key rotation

Pass a list of keys: the first one signs, all of them verify. Add the new key in front, then remove the old one once a `ttl` has passed.

## Authentication level

`set_cookie(response, value, acr=..., amr=...)` signs the login's level and methods into the cookie, for [`stepped_up()`](step-up.md#second-factor-on-a-cookie-session). Cookies set by earlier releases keep working until they expire; they carry no level, so they never pass `stepped_up()`.

## Revocable sessions

A signed cookie stays valid until it expires; `delete_cookie` only clears one browser. To end a session for real, set `session_id=True`: each `set_cookie` creates a random id, returns it, and passes it to your validator.

```python
--8<-- "docs_src/cookie_sessions/revocable.py"
```

Call `start_session` from your login route once the password matches, as in the first example. Every `set_cookie` creates a new id, including a re-issue after [step-up](step-up.md#second-factor-on-a-cookie-session), so move a stored session to the id it returns. You decide where the ids live and what "revoked" means. `session_id_of(request)` returns the current id; the [Sign out everywhere](../recipes/sign-out-everywhere.md) recipe builds a device list with it.
