import os

from fastapi import FastAPI, Security

from fastapi_multiauth import (
    APIKeyCookieAuth,
    HTTPBearerAuth,
    UnauthorizedError,
    hash_token,
)

SECRET_KEY = os.environ["SECRET_KEY"]
TOKEN_HASHES: dict[str, str] = {}


async def validate_session(username: str) -> str:
    return username


async def validate_token(token: str) -> str:
    owner = TOKEN_HASHES.get(hash_token(token))
    if owner is None:
        raise UnauthorizedError()
    return owner


session = APIKeyCookieAuth(
    name="__Host-session", validator=validate_session, secret_key=SECRET_KEY
)
user_tokens = HTTPBearerAuth(validator=validate_token, prefix="user_")

app = FastAPI()


@app.post("/tokens")
async def create_token(owner: str = Security(session)):
    token = user_tokens.generate_token()  # "user_Xk3..."
    TOKEN_HASHES[hash_token(token)] = owner  # store the hash only
    return {"token": token}  # the only time anyone sees it


@app.get("/me")
async def me(owner: str = Security(user_tokens)):
    return {"owner": owner}
