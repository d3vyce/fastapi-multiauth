import hashlib
import hmac
import os
import secrets
from typing import Annotated, TypedDict

from fastapi import FastAPI, Response, Security
from pydantic import BaseModel

from fastapi_multiauth import (
    APIKeyCookieAuth,
    HTTPBearerAuth,
    MultiAuth,
    UnauthorizedError,
    hash_token,
)

SECRET_KEY = os.environ["SECRET_KEY"]


def hash_password(password: str, salt: bytes | None = None) -> bytes:
    salt = salt or secrets.token_bytes(16)
    return salt + hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)


def check_password(password: str, stored: bytes) -> bool:
    return hmac.compare_digest(hash_password(password, stored[:16]), stored)


class User(TypedDict):
    name: str
    password: bytes


USERS: dict[str, User] = {
    "alice": {"name": "alice", "password": hash_password("wonderland")}
}
NO_PASSWORD = hash_password("")
TOKEN_HASHES = {hash_token("user_alice-script-token"): "alice"}


class Credentials(BaseModel):
    username: str
    password: str


async def validate_session(username: str) -> dict:
    if username not in USERS:
        raise UnauthorizedError()
    return {"name": username}


async def validate_api_token(token: str) -> dict:
    username = TOKEN_HASHES.get(hash_token(token))
    if username is None:
        raise UnauthorizedError()
    return {"name": username}


session = APIKeyCookieAuth(
    name="__Host-session", validator=validate_session, secret_key=SECRET_KEY
)
api_tokens = HTTPBearerAuth(validator=validate_api_token, prefix="user_")
auth = MultiAuth(api_tokens, session)

CurrentUser = Annotated[dict, Security(auth)]

app = FastAPI()


@app.post("/login")
async def login(credentials: Credentials, response: Response):
    user = USERS.get(credentials.username)
    stored = user["password"] if user else NO_PASSWORD
    if not check_password(credentials.password, stored) or user is None:
        raise UnauthorizedError()
    session.set_cookie(response, credentials.username)
    return {"ok": True}


@app.get("/me")
async def me(user: CurrentUser):
    return user
