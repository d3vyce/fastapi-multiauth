from fastapi import FastAPI, Security

from fastapi_multiauth import (
    ForbiddenError,
    HTTPBearerAuth,
    UnauthorizedError,
    hash_token,
)

USERS = {
    hash_token("alice-token"): {"name": "alice", "role": "admin"},
    hash_token("bob-token"): {"name": "bob", "role": "member"},
}


async def validate_token(token: str, *, role: str | None = None) -> dict:
    user = USERS.get(hash_token(token))
    if user is None:
        raise UnauthorizedError()
    if role is not None and user["role"] != role:
        raise ForbiddenError()
    return user


bearer = HTTPBearerAuth(validator=validate_token)

app = FastAPI()


@app.get("/me")
async def me(user: dict = Security(bearer)):
    return user


@app.get("/admin")
async def admin(user: dict = Security(bearer.require(role="admin"))):
    return user
