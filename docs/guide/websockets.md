---
icon: lucide/radio-tower
---

# WebSockets

Every source works on `@app.websocket` routes, the same way as on HTTP routes:

```python
--8<-- "docs_src/websockets/ws.py"
```

A missing or invalid credential refuses the connection before `accept()`.

Three differences from HTTP:

- **The credential is checked once**, when the connection opens. A long-lived connection outlives a revoked session unless your route closes it.
- **Browsers cannot set headers** on a WebSocket. Use a cookie, or a short-lived ticket in the query string (see the [WebSocket tickets](../recipes/websocket-tickets.md) recipe).
- **CORS does not apply.** Any page can open the socket, and the browser attaches the cookie. With a cookie, set [`csrf=True`](cookie-sessions.md#csrf) as above: the handshake must come from your origin or one in `trusted_origins`.
