---
icon: lucide/flask-conical
---

# Testing

Given this app:

```python title="main.py"
--8<-- "docs_src/testing/main.py"
```

Here are three ways to test it:

```python title="test_main.py"
--8<-- "docs_src/testing/test_main.py"
```

`test_admin_with_override`
:   A source is a normal FastAPI dependency, so `app.dependency_overrides` replaces it. Use the **same object** as the route: `require()` and `optional()` return copies, so assign the copy to a name first, as `admin` is here.

`test_admin_requires_a_token`
:   Check the protection itself: status code and `WWW-Authenticate` header.

`test_login_then_me`
:   Session cookies are `Secure`, so the test client needs an `https://` base URL to send them back.

To make sure no route is left unprotected, see the [audit recipe](../recipes/audit-routes.md).
