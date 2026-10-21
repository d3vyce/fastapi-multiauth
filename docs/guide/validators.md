---
icon: lucide/user-check
---

# Validators

Every source wraps a **validator**: a function you write that turns a credential into a user.

## The contract

A validator receives the credential and returns the user (any object), or raises to refuse it. It can be sync or async.

```python
--8<-- "docs_src/validators/contract.py"
```

- Raise [`UnauthorizedError`][fastapi_multiauth.UnauthorizedError] (401) when the credential is missing or invalid.
- Raise [`ForbiddenError`][fastapi_multiauth.ForbiddenError] (403) when it is valid, but not allowed here.

The library adds the `WWW-Authenticate` header to 401 responses for you.

## Extra arguments

Keyword arguments given to a source are passed to its validator. `require()` returns a copy of the source with more of them, to tighten a single route:

```python
--8<-- "docs_src/validators/require.py"
```

`scopes`, `session_id` and `request` are reserved names: the library fills them in itself.

## Reaching the request

Declare a `request` parameter to receive the current request, for example to leave data on `request.state` for the route:

```python
--8<-- "docs_src/validators/request.py"
```

Keep the `None` default: a validator can also be called outside a request, from a script or a background job.
