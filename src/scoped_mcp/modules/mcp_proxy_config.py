"""mcp_proxy config keys, their validation, and the result-attribute extractor.

Kept out of ``mcp_proxy.py`` so ``manifest.py`` can validate these keys at load (and in
``scoped-mcp validate``) without importing FastMCP.

forward_identity
    ``true`` adds three per-call request headers to an HTTP upstream: ``X-Forge-Run-Id``
    and ``X-Forge-Task-Id`` (each only when it validated as a UUID; a missing one is
    omitted, never sent empty) and ``X-Forge-Session-Id`` (scoped-mcp's per-client session
    id). Off by default: an upstream never receives a deployment's run ids unless its
    manifest block asks for them. **Attribution, not authorization** — see
    docs/threat-model.md.

result_attributes
    A list of ``{tool, path, transform, name}``. After a successful call of ``tool``, the
    values at ``path`` in the result are transformed and counted, and the counts are
    recorded on the audit record (``result_attrs: {name: {value: count}}``) and as one span
    attribute (``scoped_mcp.result.<name>``). Nothing else from the result is recorded, and
    the result returned to the agent is not changed.

The caps below are constants on purpose (githost-scoped-2026-11 p2): a manifest cannot
raise them.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

#: Every key McpProxyModule reads from its config. A key outside this set is ignored by
#: the module, so it is reported at startup (``mcp_proxy_unknown_config_key``) rather
#: than accepted in silence — a misspelt ``forward_identity`` would otherwise just do
#: nothing. tests/test_modules/test_mcp_proxy_config.py fails when mcp_proxy.py reads a
#: key that is not listed here.
KNOWN_CONFIG_KEYS = frozenset(
    {
        "url",
        "command",
        "args",
        "env",
        "headers",
        "tool_allowlist",
        "tool_denylist",
        "discovery_timeout_seconds",
        "max_binary_bytes",
        "forward_identity",
        "result_attributes",
    }
)

RUN_ID_HEADER = "X-Forge-Run-Id"
TASK_ID_HEADER = "X-Forge-Task-Id"
SESSION_ID_HEADER = "X-Forge-Session-Id"
FORWARDED_HEADERS = (RUN_ID_HEADER, TASK_ID_HEADER, SESSION_ID_HEADER)

#: The session id must match this before it is sent (the upstream validates it again).
#: scoped-mcp's own ids are uuid5 strings; the pattern leaves room for SESSION_ID.
SESSION_ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}")

#: At most this many extractors per module.
MAX_RESULT_EXTRACTORS = 8
#: At most this many distinct counted values per extractor per call; the rest is `other`.
MAX_RESULT_KEYS = 32
#: A counted value must match this, else it is counted as `other`.
RESULT_VALUE_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
OTHER = "other"

_PATH_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\[\])?(\.[A-Za-z_][A-Za-z0-9_]*(\[\])?)*")
_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,31}")
_EXTRACTOR_KEYS = frozenset({"tool", "path", "transform", "name"})
_UNKNOWN_KEY_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")


def _first_path_segment(value: Any) -> str | None:
    """``"docs/host-forge/services.md"`` → ``"docs"``. A qmd result's file is
    ``<collection>/<path>``, so this yields the collection."""
    if not isinstance(value, str):
        return None
    head = value.lstrip("/").split("/", 1)[0]
    return head or None


#: The closed set of transforms. Add here, nowhere else.
TRANSFORMS: dict[str, Callable[[Any], str | None]] = {
    "first_path_segment": _first_path_segment,
}


def unknown_keys(config: dict[str, Any]) -> list[str]:
    """Config keys McpProxyModule does not read, as names safe to log."""
    out = []
    for key in config:
        if key in KNOWN_CONFIG_KEYS:
            continue
        name = str(key)
        out.append(name if _UNKNOWN_KEY_RE.fullmatch(name) else "<unprintable>")
    return sorted(out)


def validate_proxy_config(config: dict[str, Any]) -> list[str]:
    """Problems with ``forward_identity`` / ``result_attributes``, one string each.

    Shared by manifest validation and McpProxyModule.__init__, so ``scoped-mcp validate``
    refuses what the module would refuse at startup.
    """
    errors: list[str] = []
    forward = config.get("forward_identity", False)
    if not isinstance(forward, bool):
        errors.append("forward_identity must be true or false")
    elif forward:
        static = {str(k).lower() for k in (config.get("headers") or {})}
        clash = [h for h in FORWARDED_HEADERS if h.lower() in static]
        if clash:
            errors.append(
                "headers must not set "
                + ", ".join(clash)
                + " when forward_identity is true: a static value would mask the real one"
            )

    extractors = config.get("result_attributes")
    if extractors is None:
        return errors
    if not isinstance(extractors, list):
        errors.append("result_attributes must be a list")
        return errors
    if len(extractors) > MAX_RESULT_EXTRACTORS:
        errors.append(
            f"result_attributes has {len(extractors)} entries; at most {MAX_RESULT_EXTRACTORS}"
        )
    names: set[str] = set()
    for i, ext in enumerate(extractors):
        where = f"result_attributes[{i}]"
        if not isinstance(ext, dict):
            errors.append(f"{where} must be a mapping of tool, path, transform, name")
            continue
        if set(ext) != _EXTRACTOR_KEYS:
            errors.append(f"{where} must have exactly the keys tool, path, transform, name")
            continue
        if not isinstance(ext["tool"], str) or not ext["tool"]:
            errors.append(f"{where}.tool must be a non-empty string")
        if not isinstance(ext["path"], str) or not _PATH_RE.fullmatch(ext["path"]):
            errors.append(
                f"{where}.path must be a dotted path with optional [] on a segment, "
                "e.g. results[].file"
            )
        # Type first: `in TRANSFORMS` on a list or mapping raises TypeError.
        if not isinstance(ext["transform"], str) or ext["transform"] not in TRANSFORMS:
            errors.append(f"{where}.transform must be one of: {', '.join(sorted(TRANSFORMS))}")
        name = ext["name"]
        if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
            errors.append(f"{where}.name must match [a-z][a-z0-9_]{{0,31}}")
        elif name in names:
            errors.append(f"{where}.name {name!r} is used twice")
        else:
            names.add(name)
    return errors


class ResultAttrError(Exception):
    """An extractor could not read the result. Its class name is what gets recorded."""


class ResultNotJson(ResultAttrError):
    pass


class PathMissing(ResultAttrError):
    pass


def _steps(path: str) -> list[tuple[str, bool]]:
    return [(seg.removesuffix("[]"), seg.endswith("[]")) for seg in path.split(".")]


def _walk(node: Any, steps: list[tuple[str, bool]]) -> list[Any]:
    if not steps:
        return [node]
    (key, is_array), rest = steps[0], steps[1:]
    if not isinstance(node, dict) or key not in node:
        raise PathMissing(key)
    child = node[key]
    if not is_array:
        return _walk(child, rest)
    if not isinstance(child, list):
        raise PathMissing(key)
    out: list[Any] = []
    for item in child:
        out.extend(_walk(item, rest))
    return out


def result_payload(structured: Any, content: list[Any] | None) -> Any:
    """The result as JSON: ``structuredContent``, else the first text block parsed."""
    if structured is not None:
        return structured
    for block in content or []:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            try:
                return json.loads(text)
            except ValueError as exc:
                raise ResultNotJson("text") from exc
    raise ResultNotJson("no text block")


def count_values(payload: Any, path: str, transform: str) -> dict[str, int]:
    """``{value: count}`` for the transformed values at ``path``, bounded.

    A value that does not match RESULT_VALUE_RE, or arrives after MAX_RESULT_KEYS distinct
    values, is counted as ``other``. Raises ResultAttrError when the path is missing.
    """
    fn = TRANSFORMS[transform]
    counts: dict[str, int] = {}
    for raw in _walk(payload, _steps(path)):
        value = fn(raw)
        key = value if value is not None and RESULT_VALUE_RE.fullmatch(value) else OTHER
        # MAX_RESULT_KEYS - 1 named values, so the total with `other` stays within the cap.
        named = len(counts) - (OTHER in counts)
        if key not in counts and key != OTHER and named >= MAX_RESULT_KEYS - 1:
            key = OTHER
        counts[key] = counts.get(key, 0) + 1
    return counts
