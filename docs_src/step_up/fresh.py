import hashlib
import hmac
import os
import secrets
from typing import Annotated, TypedDict

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
    password: bytes
    generation: int


USERS: dict[str, User] = {
    "alice": {"password": hash_password("wonderland"), "generation": 0}
}


class Password(BaseModel):
    password: str


async def validate_session(value: str) -> str:
    username, _, generation = value.rpartition(":")
    user = USERS.get(username)
    if user is None or generation != str(user["generation"]):
        raise UnauthorizedError()
    return username


session = APIKeyCookieAuth(
    name="__Host-session", validator=validate_session, secret_key=SECRET_KEY
)
FreshUser = Annotated[str, Security(session.fresh(max_age=300))]

app = FastAPI()


def sign_in(response: Response, username: str) -> None:
    session.set_cookie(response, f"{username}:{USERS[username]['generation']}")


@app.post("/me/re-auth")
async def re_auth(
    body: Password, response: Response, username: str = Security(session)
):
    if not check_password(body.password, USERS[username]["password"]):
        raise UnauthorizedError()
    sign_in(response, username)  # a new login time
    return {"ok": True}


@app.post("/me/password")
async def change_password(body: Password, response: Response, username: FreshUser):
    USERS[username]["password"] = hash_password(body.password)
    USERS[username]["generation"] += 1
    sign_in(response, username)
    return {"ok": True}
