from typing import Any

from fastapi.testclient import TestClient


def browser(app: Any, **kwargs: Any) -> TestClient:
    """A test client sending `Sec-Fetch-Site: same-origin`, as a browser on the app does.

    Cookie sources refuse a request without it or an `Origin`, unless `csrf=False`.
    """
    headers = {"Sec-Fetch-Site": "same-origin", **kwargs.pop("headers", {})}
    return TestClient(app, headers=headers, **kwargs)
