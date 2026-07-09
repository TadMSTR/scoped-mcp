"""scoped-mcp: Per-agent scoped MCP tool proxy with credential isolation and audit logging."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("scoped-mcp")
except PackageNotFoundError:
    # Not installed (e.g. running from a source checkout without `pip install -e .`).
    __version__ = "0.0.0+unknown"
