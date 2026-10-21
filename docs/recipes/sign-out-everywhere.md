# Sign out everywhere

A list of the user's devices, with a button to end every other session. Built on [revocable sessions](../guide/cookie-sessions.md#revocable-sessions).

```python
--8<-- "docs_src/recipes/sign_out_everywhere.py"
```

- `session_id_of(request)` tells which session is making the request, to mark it as "this device".
- Never show the session id itself: it is a credential.
- Login checks the password as in [cookie sessions](../guide/cookie-sessions.md), and a session row is only created once it matches.
