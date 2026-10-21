# WebSocket tickets

Browsers cannot set headers on a WebSocket. When a cookie is not an option, the page asks for a short-lived ticket first, then opens the socket with it.

```python
--8<-- "docs_src/recipes/websocket_tickets.py"
```

Tickets expire after 30 seconds and work once, so one leaking into a log is harmless.
