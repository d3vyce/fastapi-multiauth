import os

from fastapi import FastAPI, Security

from fastapi_multiauth import (
    APIKeyCookieAuth,
    HTTPBearerAuth,
    MultiAuth,
    UnauthorizedError,
    hash_token,
)

SECRET_KEY = os.environ["SECRET_KEY"]
USERS = {"1": {"id": "1", "name": "alice"}}
TOKENS = {hash_token("user_alice-token"): "1"}


async def validate_token(token: str) -> dict:
    user_id = TOKENS.get(hash_token(token))
    if user_id is None:
        raise UnauthorizedError()
    return USERS[user_id]


async def validate_session(user_id: str) -> dict:
    if user_id not in USERS:
        raise UnauthorizedError()
    return USERS[user_id]


bearer = HTTPBearerAuth(validator=validate_token, prefix="user_")
session = APIKeyCookieAuth(
    name="__Host-session", validator=validate_session, secret_key=SECRET_KEY
)
auth = MultiAuth(bearer, session)

app = FastAPI()


@app.get("/me")
async def me(user: dict = Security(auth)):
    return user
