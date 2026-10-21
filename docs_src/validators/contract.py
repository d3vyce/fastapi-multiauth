from fastapi import FastAPI, Security

from fastapi_multiauth import (
    ForbiddenError,
    HTTPBearerAuth,
    UnauthorizedError,
    hash_token,
)

USERS = {
    hash_token("alice-token"): {"name": "alice", "disabled": False},
    hash_token("bob-token"): {"name": "bob", "disabled": True},
}


async def validate_token(token: str) -> dict:
    user = USERS.get(hash_token(token))
    if user is None:
        raise UnauthorizedError()  # 401: unknown or invalid
    if user["disabled"]:
        raise ForbiddenError()  # 403: valid, but not allowed
    return user


bearer = HTTPBearerAuth(validator=validate_token)

app = FastAPI()


@app.get("/me")
async def me(user: dict = Security(bearer)):
    return user
