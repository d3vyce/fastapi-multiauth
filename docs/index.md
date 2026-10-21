---
icon: lucide/house
---

# FastAPI MultiAuth

**Composable authentication sources for FastAPI.** You write the function that decides who a credential belongs to; the library extracts the credential, combines several schemes on one route, and declares all of it in OpenAPI.

No user model, no database coupling, no ready-made `/login` routes. Your store, your rules.

## Installation

=== "uv"

    ```bash
    uv add fastapi-multiauth
    ```

=== "pip"

    ```bash
    pip install fastapi-multiauth
    ```

Optional extras: `jwt` for [`JWTValidator`](guide/jwt-and-oauth2.md), `oauth` for the [OAuth login helpers](guide/oauth-login.md).

## A first route

One route that accepts either an API token or a browser session cookie:

```python
--8<-- "docs_src/quickstart.py"
```

- A **validator** is a function you write: it receives the credential and returns the user, or raises to refuse it.
- `HTTPBearerAuth(..., prefix="user_")` reads `Authorization: Bearer user_...` tokens.
- `APIKeyCookieAuth` reads a signed cookie; your validator only sees the value once the signature checks out. `SECRET_KEY` must hold at least 32 random bytes, e.g. from `secrets.token_urlsafe(32)`.
- `MultiAuth` uses whichever one the request carries, and both appear in `/docs`.

## What you get

<div class="grid cards" markdown>

-   :lucide-key-round: **Every standard scheme**

    ---

    Bearer tokens, signed cookies, API keys, HTTP Basic, OAuth 2.0 and OpenID Connect.

    [:octicons-arrow-right-24: Guide](guide/index.md)

-   :lucide-layers: **Several schemes, one route**

    ---

    `MultiAuth` tries sources in order and documents all of them.

    [:octicons-arrow-right-24: Combining sources](guide/multiauth.md)

-   :lucide-timer: **Step-up authentication**

    ---

    Demand a recent or stronger login on sensitive routes.

    [:octicons-arrow-right-24: Step-up](guide/step-up.md)

-   :lucide-shield-check: **Fails closed**

    ---

    Weak secrets, missing HTTPS and unenforceable scopes are refused, never skipped.

    [:octicons-arrow-right-24: Security model](security-model.md)

</div>

Coming from `fastapi.security`, fastapi-users or AuthX? See the [comparison](guide/comparison.md).
