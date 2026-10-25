import hashlib
import hmac
import os
import secrets
from typing import TypedDict

from fastapi import FastAPI, Response, Security
from pydantic import BaseModel

from fastapi_multiauth import APIKeyCookieAuth, UnauthorizedError

SECRET_KEY = os.environ["SECRET_KEY"]


def hash_password(password: str, salt: bytes | None = None) -> bytes:
    salt = salt or secrets.token_bytes(16)
    return salt + hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)


def check_password(password: str, stored: bytes) -> bool:
    return hmac.compare_digest(hash_password(password, stored[:16]), stored)


class User(TypedDict):
    id: str
    name: str
    password: bytes


USERS: dict[str, User] = {
    "alice": {"id": "1", "name": "alice", "password": hash_password("wonderland")}
}
NO_PASSWORD = hash_password("")


async def validate_session(user_id: str) -> dict:
    for user in USERS.values():
        if user["id"] == user_id:
            return {"id": user["id"], "name": user["name"]}
    raise UnauthorizedError()


class Credentials(BaseModel):
    username: str
    password: str


session = APIKeyCookieAuth(
    name="__Host-session", validator=validate_session, secret_key=SECRET_KEY
)

app = FastAPI()


@app.post("/login")
async def login(credentials: Credentials, response: Response):
    user = USERS.get(credentials.username)
    stored = user["password"] if user else NO_PASSWORD
    if not check_password(credentials.password, stored) or user is None:
        raise UnauthorizedError()
    session.set_cookie(response, user["id"])
    return {"ok": True}


@app.post("/logout")
async def logout(response: Response):
    session.delete_cookie(response)
    return {"ok": True}


@app.get("/me")
async def me(user: dict = Security(session)):
    return user
