"""Shared HTTP transport hygiene for the OAuth and JWT modules."""

import contextlib
from typing import Any
from urllib.parse import urlsplit

import httpx

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

DEFAULT_TIMEOUT = 10.0
"""Default timeout (seconds) applied to every HTTP call made by this library."""


def _require_https(url: str, description: str) -> str:
    """Reject a URL that is not a string, or would send credentials over HTTP."""
    if not isinstance(url, str):
        raise ValueError(f"{description} must be a string URL (got {url!r})")  # noqa: TRY004
    parsed = urlsplit(url)
    if parsed.scheme == "https":
        return url
    if parsed.scheme == "http" and parsed.hostname in _LOOPBACK_HOSTS:
        return url
    raise ValueError(f"{description} must use https:// (got {url!r})")


async def _request_json(
    method: str,
    url: str,
    *,
    timeout: float,
    error_cls: type[Exception],
    description: str,
    headers: dict[str, str] | None = None,
    data: dict[str, str] | None = None,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Send a request and decode the JSON object body, mapping failures to `error_cls`."""
    async with (
        contextlib.nullcontext(client)
        if client is not None
        else httpx.AsyncClient(timeout=timeout)
    ) as http:
        try:
            resp = await http.request(method, url, headers=headers, data=data)
            resp.raise_for_status()
            body = resp.json()
        except httpx.HTTPError as exc:
            raise error_cls(f"failed to fetch {description}: {exc}") from exc
        except ValueError as exc:
            raise error_cls(f"{description} is not valid JSON") from exc
    if not isinstance(body, dict):
        raise error_cls(f"{description} is not a JSON object")
    return body


async def _get_json(
    url: str,
    *,
    timeout: float,
    error_cls: type[Exception],
    description: str,
    headers: dict[str, str] | None = None,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """GET `url` and decode the JSON object body, mapping failures to `error_cls`."""
    return await _request_json(
        "GET",
        url,
        timeout=timeout,
        error_cls=error_cls,
        description=description,
        headers=headers,
        client=client,
    )
