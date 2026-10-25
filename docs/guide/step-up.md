---
icon: lucide/timer
---

# Step-up authentication

Some routes can take over an account: changing the password, adding a second factor, creating an API token. A valid session is not enough there; you want proof the user logged in **recently**, or **strongly enough**.

## Recent login: `fresh()`

```python
--8<-- "docs_src/step_up/fresh.py"
```

`session.fresh(max_age=300)` accepts only a login from the last 5 minutes. An older one gets a **401** (logging in again fixes it), and the re-auth route issues a new cookie, which counts as a new login. The cookie also carries the user's `generation`: a password change increments it, which ends every other session, and signs the current one back in.

A signed cookie knows when it was set. Other sources need to be told where the login time is, with `authenticated_at=`:

```python
bearer.fresh(max_age=300, authenticated_at=lambda claims: claims.get("auth_time"))
```

!!! warning
    Only issue a new credential on a real login. Refreshing it silently on a timer makes the user look fresh forever.

## Strong login: `stepped_up()`

`stepped_up()` asks *how* the user logged in, from the token's `acr` claim:

```python
--8<-- "docs_src/step_up/stepped_up.py"
```

A weaker login gets a 401 whose `WWW-Authenticate` header names the required level (`acr_values="urn:mfa"`), so the client can send the user back to the provider. To check the methods used (the `amr` claim), compare against [`AuthenticationMethodReference`][fastapi_multiauth.AuthenticationMethodReference].

## Second factor on a cookie session

A signed cookie carries its own level: pass `acr=` and `amr=` to `set_cookie`, and `stepped_up()` reads them back without an `acr=` reader:

```python
--8<-- "docs_src/step_up/second_factor.py"
```

Call `sign_in` from your login route once the password matches: the session starts at `aal1`. The OTP route re-issues the cookie at `aal2`, adding `otp` to the methods it already had, and `/payouts` refuses anything less. The level names are yours to pick; these follow [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html).

`session.acr_of(request)` and `session.amr_of(request)` read the current cookie's level and methods. Both are signed with the value, so the client cannot raise its own level, and a cookie set without them never passes `stepped_up()`.

## Good to know

- `fresh()` and `stepped_up()` can be chained, and work on `MultiAuth` too.
- Neither works with `optional()`.
- Refusals raise [`StaleCredentialError`][fastapi_multiauth.StaleCredentialError] or [`InsufficientAuthenticationError`][fastapi_multiauth.InsufficientAuthenticationError].
