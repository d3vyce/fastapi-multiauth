"""API key header authentication source."""

from collections.abc import Callable
from typing import Any

from fastapi.requests import HTTPConnection
from fastapi.security import APIKeyHeader

from ..abc import ValidatedAuthSource


class APIKeyHeaderAuth(ValidatedAuthSource):
    """Authentication source for an API key in a request header.

    Args:
        name: Header name, e.g. `"X-API-Key"`.
        validator: Sync or async callable returning the identity, or raising to refuse.
        scheme_name: Name of the security scheme in OpenAPI, `APIKeyHeader_{name}` by default.
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
            APIKeyHeader(
                name=name,
                auto_error=False,
                scheme_name=scheme_name or f"APIKeyHeader_{name}",
                description=description,
            ),
            **kwargs,
        )

    async def extract(self, request: HTTPConnection) -> str | None:
        """Return the header value, or `None` when absent or empty."""
        return request.headers.get(self._name) or None
