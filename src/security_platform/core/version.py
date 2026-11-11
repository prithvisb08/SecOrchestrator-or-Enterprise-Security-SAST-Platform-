import importlib.metadata

_VERSION: str | None = None


def get_version() -> str:
    """Returns the platform version as a single source of truth."""
    global _VERSION
    if _VERSION is None:
        try:
            _VERSION = importlib.metadata.version("security_platform")
        except importlib.metadata.PackageNotFoundError:
            _VERSION = "1.0.0"
    return _VERSION


__version__ = get_version()
