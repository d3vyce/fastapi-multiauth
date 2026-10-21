from fastapi import FastAPI, Security

from fastapi_multiauth import ForbiddenError, HTTPBearerAuth, UnauthorizedError

TOKENS = {
    "writer-token": ("alice", {"posts:read", "posts:write"}),
    "reader-token": ("bob", {"posts:read"}),
}


async def validate_token(token: str, scopes: list[str]) -> str:
    if token not in TOKENS:
        raise UnauthorizedError()
    username, granted = TOKENS[token]
    if not set(scopes) <= granted:
        raise ForbiddenError("Missing scope")
    return username


bearer = HTTPBearerAuth(validate_token)

app = FastAPI()


@app.get("/posts")
async def list_posts(username: str = Security(bearer, scopes=["posts:read"])):
    return []


@app.post("/posts")
async def create_post(username: str = Security(bearer, scopes=["posts:write"])):
    return {"author": username}
