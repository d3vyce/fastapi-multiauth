from fastapi import FastAPI, Security
from fastapi.requests import HTTPConnection
from fastapi.security import APIKeyHeader

from fastapi_multiauth import AuthSource, UnauthorizedError

CLIENTS = {"ab:cd:ef": "billing-service"}


class ClientCertAuth(AuthSource):
    def __init__(self) -> None:
        super().__init__(APIKeyHeader(name="X-Client-Cert", scheme_name="ClientCert"))

    async def extract(self, request: HTTPConnection) -> str | None:
        return request.headers.get("X-Client-Cert") or None

    async def authenticate(self, credential: str) -> str:
        client = CLIENTS.get(credential)
        if client is None:
            raise UnauthorizedError()
        return client


client_cert = ClientCertAuth()

app = FastAPI()


@app.get("/invoices")
async def invoices(client: str = Security(client_cert)):
    return {"client": client}
