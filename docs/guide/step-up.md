---
icon: lucide/timer
---

# Step-up authentication

Some routes can take over an account: changing the password, adding a second factor, creating an API token. A valid session is not enough there; you want proof the user logged in **recently**, or **strongly enough**.

## Recent login: `fresh()`

```python
--8<-- "docs_src/step_up/fresh.py"
```

`session.fresh(300)` accepts only a login from the last 5 minutes. An older one gets a **401** (logging in again fixes it), and the re-auth route issues a new cookie, which counts as a new login.

A signed cookie knows when it was set. Other sources need to be told where the login time is, with `authenticated_at=`:

```python
bearer.fresh(300, authenticated_at=lambda claims: claims.get("auth_time"))
```

!!! warning
    Only issue a new credential on a real login. Refreshing it silently on a timer makes the user look fresh forever.

## Strong login: `stepped_up()`

`stepped_up()` asks *how* the user logged in, from the token's `acr` claim:

```python
--8<-- "docs_src/step_up/stepped_up.py"
```

A weaker login gets a 401 whose `WWW-Authenticate` header names the required level (`acr_values="urn:mfa"`), so the client can send the user back to the provider. To check the methods used (the `amr` claim), compare against [`AuthenticationMethodReference`][fastapi_multiauth.AuthenticationMethodReference].

## Good to know

- `fresh()` and `stepped_up()` can be chained, and work on `MultiAuth` too.
- Neither works with `optional()`.
- Refusals raise [`StaleCredentialError`][fastapi_multiauth.StaleCredentialError] or [`InsufficientAuthenticationError`][fastapi_multiauth.InsufficientAuthenticationError]; add an exception handler to answer in your own format.
