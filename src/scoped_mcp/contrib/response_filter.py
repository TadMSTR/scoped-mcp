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

logger = structlog.get_logger("audit")

_REDACT_PLACEHOLDER = "[REDACTED]"
_MAX_DECODED_BYTES = 64 * 1024  # 64 KiB cap, matching arg_filter.py

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


def _b64_decode(value: str, urlsafe: bool) -> str | None:
    """Decode base64 value or return None if oversized or malformed."""
    if (len(value) * 3) // 4 > _MAX_DECODED_BYTES:
        return None
    try:
        if urlsafe:
            padded = value + "=" * (-len(value) % 4)
            decoded = base64.urlsafe_b64decode(padded)
        else:
            decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error):
        return None
    if len(decoded) > _MAX_DECODED_BYTES:
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
    string to avoid returning decoded content to the caller.
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
            logger.warning(
                "response_filter_redacted",
                agent_id=agent_id,
                tool=tool_name,
                filter_name=rule.name,
            )
            # Redact on the original value, not the decoded candidate.
            return rule.pattern.sub(_REDACT_PLACEHOLDER, value)

        break  # unreachable, but satisfies exhaustiveness

    return value


def _filter_value(
    value: Any,
    rules: list[_CompiledRule],
    tool_name: str,
    agent_id: str,
) -> Any:
    """Recursively filter string values in a response tree.

    Only string leaves are tested — dict keys, numeric values, booleans, and
    None pass through unchanged. This prevents redaction from corrupting
    serialised JSON or structured response objects.
    """
    if isinstance(value, str):
        for rule in rules:
            value = _apply_rule_to_string(value, rule, tool_name, agent_id)
        return value
    if isinstance(value, dict):
        return {k: _filter_value(v, rules, tool_name, agent_id) for k, v in value.items()}
    if isinstance(value, list):
        return [_filter_value(item, rules, tool_name, agent_id) for item in value]
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
