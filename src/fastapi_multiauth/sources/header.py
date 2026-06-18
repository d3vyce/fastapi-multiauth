"""API key header authentication source."""

from typing import Any, Callable

from fastapi import Request
from fastapi.security import APIKeyHeader

from ..abc import ValidatedAuthSource


class APIKeyHeaderAuth(ValidatedAuthSource):
    """API key header authentication source (wraps ``APIKeyHeader`` for OpenAPI).

    The validator is called as ``await validator(api_key, **kwargs)``.

    Args:
        name: HTTP header name that carries the API key (e.g. ``"X-API-Key"``).
        validator: Sync or async callable returning the identity; raises
            :class:`~fastapi_multiauth.exceptions.UnauthorizedError` on failure.
        scheme_name: OpenAPI security scheme name (default ``APIKeyHeader_{name}``).
        **kwargs: Extra keyword arguments forwarded to the validator on every call.
    """

    def __init__(
        self,
        name: str,
        validator: Callable[..., Any],
        *,
        scheme_name: str | None = None,
        **kwargs: Any,
    ) -> None:
        self._name = name
        super().__init__(
            validator,
            APIKeyHeader(
                name=name,
                auto_error=False,
                scheme_name=scheme_name or f"APIKeyHeader_{name}",
            ),
            **kwargs,
        )

    async def extract(self, request: Request) -> str | None:
        """Return the API key from the configured header, or ``None`` when absent or empty."""
        return request.headers.get(self._name) or None
