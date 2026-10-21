"""API key query-string authentication source."""

from collections.abc import Callable
from typing import Any

from fastapi.requests import HTTPConnection
from fastapi.security import APIKeyQuery

from ..abc import ValidatedAuthSource


class APIKeyQueryAuth(ValidatedAuthSource):
    """Authentication source for an API key in the query string.

    Warning:
        Query strings end up in access logs, browser history and `Referer`
        headers. Use this only for clients that cannot set a header.

    Args:
        name: Query parameter name, e.g. `"api_key"`.
        validator: Sync or async callable returning the identity, or raising to refuse.
        scheme_name: Name of the security scheme in OpenAPI, `APIKeyQuery_{name}` by default.
        description: Description of the security scheme in OpenAPI.
        **kwargs: Keyword arguments passed to the validator on every call.
    """

    def __init__(
        self,
        name: str,
        validator: Callable[..., Any],
        *,
        scheme_name: str | None = None,
        description: str | None = None,
        **kwargs: Any,
    ) -> None:
        self._name = name
        super().__init__(
            validator,
            APIKeyQuery(
                name=name,
                auto_error=False,
                scheme_name=scheme_name or f"APIKeyQuery_{name}",
                description=description,
            ),
            **kwargs,
        )

    async def extract(self, request: HTTPConnection) -> str | None:
        """Return the query parameter value, or `None` when absent or empty."""
        return request.query_params.get(self._name) or None
