"""Bearer token authentication sources."""

import secrets
from collections.abc import Callable
from typing import Any

from fastapi.requests import HTTPConnection
from fastapi.security import HTTPBearer

from fastapi_multiauth.exceptions import UnauthorizedError

from ..abc import ValidatedAuthSource
from ..utils import authorization_credential


class _BearerSource(ValidatedAuthSource):
    """Extraction shared by every source carrying an `Authorization: Bearer` token."""

    _prefix: str | None = None

    def www_authenticate(self) -> str:
        """Return the `Bearer` challenge, as RFC 6750 defines it."""
        return "Bearer"

    async def extract(self, request: HTTPConnection) -> str | None:
        """Return the bearer token, or `None` when absent, empty, or without the prefix.

        The `Bearer` scheme is matched case-insensitively, and the prefix is
        kept in the returned token.
        """
        token = authorization_credential(request, "bearer")
        if token is None:
            return None
        if self._prefix is not None and not token.startswith(self._prefix):
            return None
        return token

    async def authenticate_scoped(
        self,
        credential: str,
        scopes: list[str],
        *,
        request: HTTPConnection | None = None,
    ) -> Any:
        """Validate the token, passing the route's scopes and request on."""
        if self._prefix is not None and not credential.startswith(self._prefix):
            raise UnauthorizedError()
        return await self._call_validator(credential, scopes=scopes, request=request)


class HTTPBearerAuth(_BearerSource):
    """Authentication source for `Authorization: Bearer` tokens.

    Args:
        validator: Sync or async callable returning the identity, or raising to refuse.
        prefix: Only accept tokens starting with this, e.g. `"user_"`. The
            prefix stays in the token the validator receives.
        scheme_name: Name of the security scheme in OpenAPI, `HTTPBearer` by default. Give each
            source its own name when several share an app.
        description: Description of the security scheme in OpenAPI.
        bearer_format: Format hint shown in OpenAPI, e.g. `"JWT"`.
        token_generator: Callable building a token body from `nbytes`, used
            by `generate_token()`. Build it on `secrets`, never `random`.
        **kwargs: Keyword arguments passed to the validator on every call.
    """

    def __init__(
        self,
        validator: Callable[..., Any],
        *,
        prefix: str | None = None,
        scheme_name: str | None = None,
        description: str | None = None,
        bearer_format: str | None = None,
        token_generator: Callable[[int], str] = secrets.token_urlsafe,
        **kwargs: Any,
    ) -> None:
        self._prefix = prefix
        self._token_generator = token_generator
        super().__init__(
            validator,
            HTTPBearer(
                auto_error=False,
                scheme_name=scheme_name,
                description=description,
                bearerFormat=bearer_format,
            ),
            **kwargs,
        )

    def generate_token(self, nbytes: int = 32) -> str:
        """Generate a new random token, with the source's prefix in front.

        Args:
            nbytes: Bytes of entropy, passed to `token_generator`.

        Returns:
            The token, e.g. `"user_Xk3..."`. Store its `hash_token()` digest,
            never the token itself.

        Raises:
            ValueError: If the generator returns an empty token, or one with
                leading or trailing whitespace.
        """
        token = self._token_generator(nbytes)
        if not token:
            raise ValueError("token_generator must return a non-empty string")
        if self._prefix is not None:
            token = f"{self._prefix}{token}"
        if token != token.strip():
            raise ValueError(
                "token_generator must not leave leading or trailing whitespace: "
                "it is stripped when the Authorization header is parsed"
            )
        return token
