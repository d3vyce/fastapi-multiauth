from fastapi import FastAPI, Security

from fastapi_multiauth import (
    ForbiddenError,
    HTTPBearerAuth,
    UnauthorizedError,
    hash_token,
)

TOKENS = {
    hash_token("writer-token"): ("alice", {"posts:read", "posts:write"}),
    hash_token("reader-token"): ("bob", {"posts:read"}),
}


async def validate_token(token: str, scopes: list[str]) -> str:
    row = TOKENS.get(hash_token(token))
    if row is None:
        raise UnauthorizedError()
    username, granted = row
    if not set(scopes) <= granted:
        raise ForbiddenError("Missing scope")
    return username


bearer = HTTPBearerAuth(validator=validate_token)

app = FastAPI()


@app.get("/posts")
async def list_posts(username: str = Security(bearer, scopes=["posts:read"])):
    return []


@app.post("/posts")
async def create_post(username: str = Security(bearer, scopes=["posts:write"])):
    return {"author": username}
