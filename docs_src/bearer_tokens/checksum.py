from fastapi import FastAPI, Security

from fastapi_multiauth import (
    HTTPBearerAuth,
    UnauthorizedError,
    checksum_token_generator,
    hash_token,
    verify_token_checksum,
)

TOKEN_HASHES: dict[str, str] = {}


async def validate_token(token: str) -> str:
    if not verify_token_checksum(token, prefix="user_"):
        raise UnauthorizedError()  # a typo: no lookup needed
    owner = TOKEN_HASHES.get(hash_token(token))
    if owner is None:
        raise UnauthorizedError()
    return owner


user_tokens = HTTPBearerAuth(
    validator=validate_token,
    prefix="user_",
    token_generator=checksum_token_generator,
)

app = FastAPI()


@app.get("/me")
async def me(owner: str = Security(user_tokens)):
    return {"owner": owner}
