from fastapi import FastAPI, Security

from fastapi_multiauth import ForbiddenError, HTTPBearerAuth, UnauthorizedError

USERS = {
    "alice-token": {"name": "alice", "role": "admin"},
    "bob-token": {"name": "bob", "role": "member"},
}


async def validate_token(token: str, *, role: str | None = None) -> dict:
    user = USERS.get(token)
    if user is None:
        raise UnauthorizedError()
    if role is not None and user["role"] != role:
        raise ForbiddenError()
    return user


bearer = HTTPBearerAuth(validate_token)

app = FastAPI()


@app.get("/me")
async def me(user: dict = Security(bearer)):
    return user


@app.get("/admin")
async def admin(user: dict = Security(bearer.require(role="admin"))):
    return user
