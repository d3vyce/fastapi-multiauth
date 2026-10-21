# Sessions and API tokens

People use the web app with a session cookie, scripts use an API token, and both reach the same routes.

```python
--8<-- "docs_src/recipes/sessions_and_tokens.py"
```

- The bearer source comes first, so API calls never touch cookie parsing.
- Only the token's hash is stored.
- Cookie-authenticated `POST` routes need [CSRF protection](../guide/cookie-sessions.md#csrf); token-authenticated ones do not.
