from typing import Annotated

from fastapi import FastAPI, Security

from fastapi_multiauth import (
    APIKeyCookieAuth,
    HTTPBearerAuth,
    UnauthorizedError,
    checksum_token_generator,
    hash_token,
    verify_token_checksum,
)

SECRET_KEY = "change-me-please-32-bytes-minimum"
TOKENS: dict[int, dict] = {}


async def validate_session(username: str) -> str:
    return username


async def validate_api_token(token: str) -> str:
    if not verify_token_checksum(token, prefix="user_"):
        raise UnauthorizedError()  # a typo: no lookup needed
    for row in TOKENS.values():
        if row["hash"] == hash_token(token):
            return row["owner"]
    raise UnauthorizedError()


session = APIKeyCookieAuth("__Host-session", validate_session, secret_key=SECRET_KEY)
api_tokens = HTTPBearerAuth(
    validate_api_token,
    prefix="user_",
    token_generator=checksum_token_generator,
)
SessionUser = Annotated[str, Security(session)]
FreshSessionUser = Annotated[str, Security(session.fresh(600))]

app = FastAPI()


@app.post("/tokens")
async def create_token(name: str, owner: FreshSessionUser):
    token = api_tokens.generate_token()
    token_id = len(TOKENS) + 1
    TOKENS[token_id] = {"name": name, "owner": owner, "hash": hash_token(token)}
    return {"id": token_id, "token": token}  # shown once, never again


@app.get("/tokens")
async def list_tokens(owner: SessionUser):
    return [
        {"id": token_id, "name": row["name"]}
        for token_id, row in TOKENS.items()
        if row["owner"] == owner
    ]


@app.delete("/tokens/{token_id}")
async def revoke_token(token_id: int, owner: SessionUser):
    if TOKENS.get(token_id, {}).get("owner") == owner:
        del TOKENS[token_id]
    return {"ok": True}


@app.get("/whoami")
async def whoami(owner: str = Security(api_tokens)):
    return {"owner": owner}
