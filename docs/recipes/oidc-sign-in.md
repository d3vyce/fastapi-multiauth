# Sign in with OpenID Connect

A "Log in with..." button for any OpenID Connect provider (Google, Keycloak, Entra ID, Authentik...). The [OAuth login flow](../guide/oauth-login.md) page explains each step.

```python
--8<-- "docs_src/recipes/oidc_sign_in.py"
```

- Identify users by `(iss, sub)`, never by email: emails change, and not every provider verifies them.
- The settings at the top come from your configuration, never from the request.
