"""Response content filtering for scoped-mcp.

Pattern-based scanning of tool response values before they reach the LLM,
with warn, redact, or block actions. Mirrors the architecture of arg_filter.py
but operates on return values rather than arguments.

The ``redact`` action replaces matched content with ``[REDACTED]`` while
preserving response structure. Redaction is applied only to string values —
never to the serialised form of dicts or lists — to avoid corrupting
structured responses from upstream tools.

Manifest config:
    response_filters:
      - name: "response-credential-leak"
        pattern: "(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|AKIA[A-Z0-9]{16})"
        action: redact
        decode: [base64]

      - name: "response-injection-attempt"
        pattern: "ignore (all |previous )?(instructions|prompt)|you are now"
        action: warn
        case_insensitive: true

Behavior:
- ``block`` raises ConfigError and logs a warning to the audit stream.
- ``warn`` lets the response through but logs a warning.
- ``redact`` substitutes matched content in string fields with ``[REDACTED]``.
- Values are NEVER logged — only ``filter_name`` and ``tool_name``.

Auto-registered when ``response_filters`` is present in the manifest and
``configure_audit(response_filter=...)`` is called at startup.
"""

from __future__ import annotations

import base64
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Literal

import structlog
from mcp.types import (
    AudioContent,
    EmbeddedResource,
    ImageContent,
    ResourceLink,
    TextContent,
)
from pydantic import ValidationError

logger = structlog.get_logger("audit")

_REDACT_PLACEHOLDER = "[REDACTED]"
_MAX_DECODED_BYTES = 64 * 1024  # 64 KiB cap, matching arg_filter.py
# Text-typed blobs are primary content, not a speculative decode candidate, so they get a
# larger cap. Above it the blob cannot be scanned and the response is blocked (audit R2-02).
_MAX_TEXT_BLOB_BYTES = 4 * 1024 * 1024

Action = Literal["block", "warn", "redact"]
DecodeStep = Literal["base64", "urlsafe_base64", "url"]


@dataclass
class _CompiledRule:
    name: str
    pattern: re.Pattern[str]
    action: Action
    decode: list[DecodeStep]


def _compile_rule(rule: dict[str, Any]) -> _CompiledRule:
    name = rule["name"]
    flags = re.IGNORECASE if rule.get("case_insensitive") else 0
    try:
        compiled = re.compile(rule["pattern"], flags)
    except re.error as e:
        raise ValueError(f"response_filters[{name!r}].pattern is not a valid regex: {e}") from e
    action = rule.get("action", "warn")
    if action not in ("block", "warn", "redact"):
        raise ValueError(
            f"response_filters[{name!r}].action must be 'block', 'warn', or 'redact', "
            f"got {action!r}"
        )
    decode = list(rule.get("decode", []))
    for step in decode:
        if step not in ("base64", "urlsafe_base64", "url"):
            raise ValueError(
                f"response_filters[{name!r}].decode entry must be one of "
                f"('base64', 'urlsafe_base64', 'url'), got {step!r}"
            )
    return _CompiledRule(name=name, pattern=compiled, action=action, decode=decode)


def _b64_decode(value: str, urlsafe: bool, max_bytes: int = _MAX_DECODED_BYTES) -> str | None:
    """Decode base64 value or return None if oversized or malformed."""
    if (len(value) * 3) // 4 > max_bytes:
        return None
    try:
        if urlsafe:
            padded = value + "=" * (-len(value) % 4)
            decoded = base64.urlsafe_b64decode(padded)
        else:
            decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error):
        return None
    if len(decoded) > max_bytes:
        return None
    return decoded.decode("utf-8", errors="replace")


def _candidate_strings(value: str, decode: list[DecodeStep]) -> list[str]:
    """Return [raw, *each successful decode]. Decode failures are silently skipped."""
    candidates = [value]
    current = value
    for step in decode:
        if step == "url":
            try:
                current = urllib.parse.unquote(current)
            except Exception:
                continue
        elif step == "base64":
            decoded = _b64_decode(current, urlsafe=False)
            if decoded is None:
                continue
            current = decoded
        elif step == "urlsafe_base64":
            decoded = _b64_decode(current, urlsafe=True)
            if decoded is None:
                continue
            current = decoded
        candidates.append(current)
    return candidates


def _apply_rule_to_string(
    value: str,
    rule: _CompiledRule,
    tool_name: str,
    agent_id: str,
) -> str:
    """Apply one rule to a string value. Returns the (possibly modified) value.

    For ``block`` and ``warn`` matches, the match is detected across decode
    candidates. For ``redact``, the substitution is applied to the raw (original)
    string to avoid returning decoded content to the caller; when only a decoded
    candidate matched, the whole value is replaced.
    """
    for candidate in _candidate_strings(value, rule.decode):
        if rule.pattern.search(candidate) is None:
            continue

        if rule.action == "block":
            logger.warning(
                "response_filter_blocked",
                agent_id=agent_id,
                tool=tool_name,
                filter_name=rule.name,
            )
            from ..exceptions import ConfigError

            raise ConfigError(f"tool response from {tool_name!r} blocked by response filter policy")

        if rule.action == "warn":
            logger.warning(
                "response_filter_warning",
                agent_id=agent_id,
                tool=tool_name,
                filter_name=rule.name,
            )
            return value  # unchanged

        if rule.action == "redact":
            # Redact on the original value, not the decoded candidate. If only a decoded
            # candidate matched (e.g. a base64-encoded credential), the raw string holds
            # nothing to substitute — replace the whole value, or the secret goes out
            # unchanged under a log line claiming it was redacted (audit R2-01).
            if rule.pattern.search(value) is not None:
                redacted = rule.pattern.sub(_REDACT_PLACEHOLDER, value)
            else:
                redacted = _REDACT_PLACEHOLDER
            logger.warning(
                "response_filter_redacted",
                agent_id=agent_id,
                tool=tool_name,
                filter_name=rule.name,
            )
            return redacted

        break  # unreachable, but satisfies exhaustiveness

    return value


# MCP content blocks. mcp_proxy returns them unchanged when a result carries an image or
# other non-text block (vikunja#1070), so every string on them must be scanned, not just
# ``.text``: ``_meta``, extra fields (all of these models are ``extra="allow"``), URIs and
# ResourceLink names/titles/descriptions reach the agent too.
_CONTENT_BLOCK_TYPES = (TextContent, ImageContent, AudioContent, ResourceLink, EmbeddedResource)

_TEXT_MIME_EXACT = frozenset({"application/json", "application/xml"})


def _is_text_mime(mime: str | None) -> bool:
    """True for blobs that may hold text: text/*, JSON, XML, or no declared type."""
    if not mime:
        return True
    base = mime.split(";", 1)[0].strip().lower()
    return base.startswith("text/") or base in _TEXT_MIME_EXACT or base.endswith(("+json", "+xml"))


def _block_response(rule_name: str, tool_name: str, agent_id: str) -> None:
    logger.warning(
        "response_filter_blocked",
        agent_id=agent_id,
        tool=tool_name,
        filter_name=rule_name,
    )
    from ..exceptions import ConfigError

    raise ConfigError(f"tool response from {tool_name!r} blocked by response filter policy")


def _scan_text_blob(
    blob: str,
    rules: list[_CompiledRule],
    tool_name: str,
    agent_id: str,
) -> None:
    """Scan a text-typed base64 blob. Any ``block`` or ``redact`` match blocks the response.

    Redacting inside base64 is not meaningful, so ``redact`` escalates to ``block`` here.
    A blob that cannot be decoded (over ``_MAX_TEXT_BLOB_BYTES``, or malformed) blocks too.
    """
    decoded = _b64_decode(blob, urlsafe=False, max_bytes=_MAX_TEXT_BLOB_BYTES)
    if decoded is None:
        # Over the text-blob cap or not valid base64: it cannot be scanned, so it does not
        # go out (audit R2-02).
        # SECURITY[accepted]: strict decode, so line-wrapped, unpadded and url-safe blobs
        # (incl. binary blobs with no mimeType) are blocked too — fail-closed over a lenient
        # decoder. Audit: 2026-10-11/scoped-mcp-proxy-content-1070 R3-02.
        _block_response("text-blob-unscannable", tool_name, agent_id)
    for rule in rules:
        for candidate in _candidate_strings(decoded, rule.decode):
            if rule.pattern.search(candidate) is None:
                continue
            if rule.action == "warn":
                logger.warning(
                    "response_filter_warning",
                    agent_id=agent_id,
                    tool=tool_name,
                    filter_name=rule.name,
                )
                break
            _block_response(rule.name, tool_name, agent_id)


def _filter_content_block(
    block: Any,
    rules: list[_CompiledRule],
    tool_name: str,
    agent_id: str,
) -> Any:
    """Filter every string on an MCP content block, then re-validate it into its type.

    Binary payloads (image/audio ``data``, resource ``blob``) are lifted out before the
    string pass so a pattern can never rewrite base64. Text-typed blobs are scanned
    decoded instead (``_scan_text_blob``). If redaction leaves a field the model rejects
    (e.g. a URI redacted whole), the response is blocked rather than forwarded unfiltered.
    """
    dumped = block.model_dump(by_alias=True, mode="json", exclude_unset=True)
    payload_holder: dict[str, Any] | None = None
    payload_key = ""
    if isinstance(block, ImageContent | AudioContent):
        payload_holder, payload_key = dumped, "data"
    elif isinstance(block, EmbeddedResource) and isinstance(
        blob := dumped["resource"].get("blob"), str
    ):
        # A real BlobResourceContents, or a `blob` riding as an extra field on a resource
        # that also has `text` (not valid MCP; mcp.types parses it as TextResourceContents).
        # Both get the blob treatment, so the extra cannot fall to the 64 KiB nested-decode
        # path and go out unscanned (audit R3-01).
        if _is_text_mime(block.resource.mimeType):
            _scan_text_blob(blob, rules, tool_name, agent_id)
        payload_holder, payload_key = dumped["resource"], "blob"
    payload = payload_holder.pop(payload_key) if payload_holder is not None else None

    filtered = _filter_value(dumped, rules, tool_name, agent_id)

    if payload_holder is not None:
        target = filtered if payload_holder is dumped else filtered["resource"]
        target[payload_key] = payload
    try:
        return type(block).model_validate(filtered)
    except ValidationError:
        _block_response("content-block-revalidation", tool_name, agent_id)


def _filter_value(
    value: Any,
    rules: list[_CompiledRule],
    tool_name: str,
    agent_id: str,
) -> Any:
    """Recursively filter string values in a response tree.

    Only string leaves are tested — dict keys, numeric values, booleans, and
    None pass through unchanged. This prevents redaction from corrupting
    serialised JSON or structured response objects. MCP content blocks are
    dumped, filtered as a dict, and re-validated (``_filter_content_block``).
    """
    if isinstance(value, str):
        for rule in rules:
            value = _apply_rule_to_string(value, rule, tool_name, agent_id)
        return value
    if isinstance(value, dict):
        # SECURITY[accepted]: keys (and so extra-field / _meta key names) are not scanned.
        # Reaching an agent through a key takes an upstream that structures output to do it,
        # not an accidental leak; if keys are ever scanned, a match must block, since a
        # redacted key can collide. Audit: 2026-10-11/scoped-mcp-proxy-content-1070 R2-03.
        return {k: _filter_value(v, rules, tool_name, agent_id) for k, v in value.items()}
    if isinstance(value, list):
        return [_filter_value(item, rules, tool_name, agent_id) for item in value]
    if isinstance(value, _CONTENT_BLOCK_TYPES):
        return _filter_content_block(value, rules, tool_name, agent_id)
    return value


class ResponseFilter:
    """Scans and optionally modifies tool responses before they reach the LLM.

    Constructed from manifest response_filter rules at startup and injected
    into the @audited decorator via configure_audit().
    """

    def __init__(self, rules: list[dict[str, Any]], agent_id: str) -> None:
        self._rules = [_compile_rule(r) for r in rules]
        self._agent_id = agent_id

    def filter_response(self, result: Any, tool_name: str, agent_id: str) -> Any:
        """Filter a tool response. Returns the (possibly modified) result."""
        if not self._rules:
            return result
        return _filter_value(result, self._rules, tool_name, agent_id)
