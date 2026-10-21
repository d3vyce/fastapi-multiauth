from fastapi import FastAPI, Security

from fastapi_multiauth import APIKeyHeaderAuth, UnauthorizedError, hash_token

CLIENTS = {hash_token("key-for-reporting"): "reporting-service"}


async def validate_api_key(key: str) -> str:
    client = CLIENTS.get(hash_token(key))
    if client is None:
        raise UnauthorizedError()
    return client


api_key = APIKeyHeaderAuth(name="X-API-Key", validator=validate_api_key)

app = FastAPI()


@app.get("/reports")
async def reports(client: str = Security(api_key)):
    return {"client": client}
