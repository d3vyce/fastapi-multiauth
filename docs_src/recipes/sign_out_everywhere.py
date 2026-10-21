import hashlib
import hmac
import os
import secrets
from typing import Annotated

from fastapi import FastAPI, Request, Response, Security
from pydantic import BaseModel

from fastapi_multiauth import APIKeyCookieAuth, UnauthorizedError

SECRET_KEY = os.environ["SECRET_KEY"]


def hash_password(password: str, salt: bytes | None = None) -> bytes:
    salt = salt or secrets.token_bytes(16)
    return salt + hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)


def check_password(password: str, stored: bytes) -> bool:
    return hmac.compare_digest(hash_password(password, stored[:16]), stored)


PASSWORDS = {"alice": hash_password("wonderland")}
NO_PASSWORD = hash_password("")
SESSIONS: dict[str, dict] = {}


class Credentials(BaseModel):
    username: str
    password: str


async def validate_session(username: str, *, session_id: str) -> str:
    if session_id not in SESSIONS:
        raise UnauthorizedError()
    return username


session = APIKeyCookieAuth(
    name="__Host-session",
    validator=validate_session,
    secret_key=SECRET_KEY,
    session_id=True,
)
CurrentUser = Annotated[str, Security(session)]

app = FastAPI()


@app.post("/login")
async def login(credentials: Credentials, request: Request, response: Response):
    stored = PASSWORDS.get(credentials.username, NO_PASSWORD)
    if (
        not check_password(credentials.password, stored)
        or credentials.username not in PASSWORDS
    ):
        raise UnauthorizedError()
    session_id = session.set_cookie(response, credentials.username)
    assert session_id is not None
    SESSIONS[session_id] = {
        "username": credentials.username,
        "device": request.headers.get("user-agent", "unknown"),
    }
    return {"ok": True}


@app.get("/sessions")
async def list_sessions(request: Request, username: CurrentUser):
    current = session.session_id_of(request)
    return [
        {"device": row["device"], "current": session_id == current}
        for session_id, row in SESSIONS.items()
        if row["username"] == username
    ]


@app.post("/sessions/revoke-others")
async def revoke_others(request: Request, username: CurrentUser):
    current = session.session_id_of(request)
    for session_id, row in list(SESSIONS.items()):
        if row["username"] == username and session_id != current:
            del SESSIONS[session_id]
    return {"ok": True}


@app.post("/logout")
async def logout(request: Request, response: Response):
    session_id = session.delete_cookie(response, request)
    SESSIONS.pop(session_id or "", None)
    return {"ok": True}
