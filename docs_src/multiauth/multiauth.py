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
TOKENS = {hash_token("user_alice-token"): "alice"}


async def validate_token(token: str) -> str:
    username = TOKENS.get(hash_token(token))
    if username is None:
        raise UnauthorizedError()
    return username


async def validate_session(username: str) -> str:
    return username


bearer = HTTPBearerAuth(validator=validate_token, prefix="user_")
session = APIKeyCookieAuth(
    name="__Host-session", validator=validate_session, secret_key=SECRET_KEY
)
auth = MultiAuth(bearer, session)

app = FastAPI()


@app.get("/me")
async def me(username: str = Security(auth)):
    return {"username": username}
