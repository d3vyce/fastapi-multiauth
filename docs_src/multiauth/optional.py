from typing import Annotated

from fastapi import FastAPI, Security

from fastapi_multiauth import HTTPBearerAuth, UnauthorizedError

EDITORS = {"editor-token": "alice"}


async def validate_token(token: str) -> str:
    if token not in EDITORS:
        raise UnauthorizedError()
    return EDITORS[token]


bearer = HTTPBearerAuth(validate_token)
MaybeEditor = Annotated[str | None, Security(bearer.optional())]

app = FastAPI()


@app.get("/articles/{slug}")
async def article(slug: str, editor: MaybeEditor):
    return {"slug": slug, "show_drafts": editor is not None}
