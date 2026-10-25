---
icon: lucide/braces
---

# JWT and OAuth 2.0

When an identity provider issues the tokens (Keycloak, Auth0, Entra ID, Authentik...), you do not write the validator: [`JWTValidator`][fastapi_multiauth.JWTValidator] checks them for you.

```bash
uv add "fastapi-multiauth[jwt]"
```

## Validate provider tokens

```python
--8<-- "docs_src/jwt/jwks.py"
```

The validator fetches the provider's public keys (the JWKS) and checks the signature, expiry, audience and issuer. Keys are cached for an hour and refreshed when the provider rotates them; if the provider is down, the cached keys keep working.

!!! warning "`audience` is required"
    A provider signs the tokens of **all** its applications with the same keys. Without an audience check, a token issued for another app would be accepted here. Use `audience=JWTValidator.ANY_AUDIENCE` only if you really mean it.

By default the route receives the token's claims. Pass `claims_to_identity=` to turn them into your own user object. For tokens you sign yourself, use `JWTValidator(secret=...)` instead of `jwks_url`.

## Opaque tokens

Some providers issue opaque tokens instead of JWTs, or let you choose them because they can be revoked. [`IntrospectionValidator`][fastapi_multiauth.IntrospectionValidator] asks the provider's [introspection endpoint](https://datatracker.ietf.org/doc/html/rfc7662) whether each token is still active:

```python
--8<-- "docs_src/jwt/introspection.py"
```

The route receives the provider's answer, which carries the same fields as JWT claims (`sub`, `scope`, `exp`...), so scopes, `fresh()` and `stepped_up()` work the same way. No extra is needed.

Active answers are cached for `cache_ttl` seconds (60 by default), never past the token's `exp`. A revoked token therefore keeps working for up to a minute; set `cache_ttl=0` to ask on every request. Inactive answers are not cached, so a client sending junk tokens costs one request to the provider each: rate-limit the routes. If the provider is down, requests get a 503.

!!! warning "`audience` is required here too"
    The provider answers for the tokens of all its applications. Many providers leave `aud` out of the answer, and then every token is refused: check what yours returns, and use `audience=IntrospectionValidator.ANY_AUDIENCE` if it has no `aud` to check.

## A real Authorize button

With `HTTPBearerAuth`, `/docs` only shows a token box. The OAuth 2.0 sources also describe the login flow and its scopes, so `/docs` can log in for real:

```python
--8<-- "docs_src/jwt/oauth2_source.py"
```

Route scopes are checked against the token's `scope` claim; a missing scope gets a 403. Also available: [`OAuth2PasswordBearerAuth`][fastapi_multiauth.OAuth2PasswordBearerAuth] and [`OpenIdConnectAuth`][fastapi_multiauth.OpenIdConnectAuth].

!!! note
    This library validates JWTs, it never issues them. To issue your own, look at [AuthX](https://github.com/yezz123/authx).
