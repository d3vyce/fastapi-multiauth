import secrets
import time
from typing import Annotated

from fastapi import FastAPI, Security, WebSocket

from fastapi_multiauth import (
    APIKeyCookieAuth,
    APIKeyQueryAuth,
    UnauthorizedError,
    hash_token,
)

SECRET_KEY = "change-me-please-32-bytes-minimum"
TICKETS: dict[str, tuple[str, float]] = {}


async def validate_session(username: str) -> str:
    return username


async def validate_ticket(ticket: str) -> str:
    username, expires_at = TICKETS.pop(hash_token(ticket), ("", 0.0))  # single use
    if expires_at < time.time():
        raise UnauthorizedError()
    return username


session = APIKeyCookieAuth("__Host-session", validate_session, secret_key=SECRET_KEY)
ticket_auth = APIKeyQueryAuth("ticket", validate_ticket)

app = FastAPI()


@app.post("/ws-ticket")
async def ws_ticket(username: Annotated[str, Security(session)]):
    ticket = secrets.token_urlsafe(32)
    TICKETS[hash_token(ticket)] = (username, time.time() + 30)
    return {"ticket": ticket}


@app.websocket("/ws")
async def ws(websocket: WebSocket, username: Annotated[str, Security(ticket_auth)]):
    await websocket.accept()
    await websocket.send_json({"hello": username})
    await websocket.close()
