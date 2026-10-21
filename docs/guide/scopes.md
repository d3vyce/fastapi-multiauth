---
icon: lucide/list-checks
---

# Scopes

Declare the scopes a route needs with `Security(source, scopes=[...])`. A validator with a `scopes` parameter receives them:

```python
--8<-- "docs_src/scopes/scopes.py"
```

Raise `ForbiddenError` (403) for a missing scope: the token is valid, it just cannot do this. [`JWTValidator`](jwt-and-oauth2.md) does this check for you.

## Fails closed

If a route declares scopes but the validator has no `scopes` parameter, the request fails with an error instead of skipping the check. A forgotten parameter shows up in your first test, not as an open route in production.

The same goes for `MultiAuth`: every source must be able to check scopes, otherwise the route would be protected or not depending on which credential the client sent.

## In `/docs`

Scopes appear on every route's security requirement. Only the [OAuth 2.0 sources](jwt-and-oauth2.md#a-real-authorize-button) can also publish the list of available scopes, which gives `/docs` its checkboxes.
