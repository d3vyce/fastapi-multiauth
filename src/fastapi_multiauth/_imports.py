"""Optional dependency helpers."""


def require_extra(package: str, extra: str) -> None:
    """Raise *ImportError* with an actionable install instruction."""
    raise ImportError(
        f"'{package}' is required to use this feature. "
        f"Install it with: pip install fastapi-multiauth[{extra}]"
    )
