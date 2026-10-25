import os

from fastapi import FastAPI, Security

from fastapi_multiauth import HTTPBearerAuth, IntrospectionValidator

ISSUER = "https://idp.example.com/realms/main"

bearer = HTTPBearerAuth(
    validator=IntrospectionValidator(
        url=f"{ISSUER}/protocol/openid-connect/token/introspect",
        client_id="my-api",
        client_secret=os.environ["INTROSPECTION_CLIENT_SECRET"],
        audience="my-api",
    )
)

app = FastAPI()


@app.get("/me")
async def me(claims: dict = Security(bearer)):
    return {"sub": claims["sub"]}
