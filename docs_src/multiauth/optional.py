from typing import Annotated

from fastapi import FastAPI, Security

from fastapi_multiauth import HTTPBearerAuth, UnauthorizedError, hash_token

EDITORS = {hash_token("editor-token"): "alice"}


async def validate_token(token: str) -> str:
    editor = EDITORS.get(hash_token(token))
    if editor is None:
        raise UnauthorizedError()
    return editor


bearer = HTTPBearerAuth(validator=validate_token)
MaybeEditor = Annotated[str | None, Security(bearer.optional())]

app = FastAPI()


@app.get("/articles/{slug}")
async def article(slug: str, editor: MaybeEditor):
    return {"slug": slug, "show_drafts": editor is not None}
