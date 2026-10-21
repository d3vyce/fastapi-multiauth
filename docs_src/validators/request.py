from fastapi import FastAPI, Request, Security

from fastapi_multiauth import HTTPBearerAuth, UnauthorizedError, hash_token

TOKENS = {hash_token("alice-token"): ("alice", 7)}


async def validate_token(token: str, request: Request | None = None) -> str:
    row = TOKENS.get(hash_token(token))
    if row is None:
        raise UnauthorizedError()
    username, token_id = row
    if request is not None:
        request.state.token_id = token_id
    return username


bearer = HTTPBearerAuth(validator=validate_token)

app = FastAPI()


@app.get("/me")
async def me(request: Request, username: str = Security(bearer)):
    return {"name": username, "token_id": request.state.token_id}
