from fastapi import FastAPI, Security

from fastapi_multiauth import HTTPBearerAuth, UnauthorizedError, hash_token

TOKEN_HASHES: dict[str, str] = {hash_token("user_first-token"): "alice"}


async def validate_token(token: str) -> str:
    owner = TOKEN_HASHES.get(hash_token(token))
    if owner is None:
        raise UnauthorizedError()
    return owner


user_tokens = HTTPBearerAuth(validate_token, prefix="user_")

app = FastAPI()


@app.post("/tokens")
async def create_token(owner: str = Security(user_tokens)):
    token = user_tokens.generate_token()  # "user_Xk3..."
    TOKEN_HASHES[hash_token(token)] = owner  # store the hash only
    return {"token": token}  # the only time anyone sees it


@app.get("/me")
async def me(owner: str = Security(user_tokens)):
    return {"owner": owner}
