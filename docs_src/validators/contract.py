from fastapi import FastAPI, Security

from fastapi_multiauth import ForbiddenError, HTTPBearerAuth, UnauthorizedError

USERS = {
    "alice-token": {"name": "alice", "disabled": False},
    "bob-token": {"name": "bob", "disabled": True},
}


async def validate_token(token: str) -> dict:
    user = USERS.get(token)
    if user is None:
        raise UnauthorizedError()  # 401: unknown or invalid
    if user["disabled"]:
        raise ForbiddenError()  # 403: valid, but not allowed
    return user


bearer = HTTPBearerAuth(validate_token)

app = FastAPI()


@app.get("/me")
async def me(user: dict = Security(bearer)):
    return user
