"""Argument content filtering middleware for scoped-mcp.

Pattern-based blocking or alerting on tool argument values, with optional
base64 / URL decoding before matching to catch obfuscated payloads.

Manifest config:
    argument_filters:
      - name: "credential-leak"
        pattern: "(password|secret|api.?key|bearer)"
        fields: ["*"]                # which argument fields to inspect; "*" = all string values
        action: block                # or "warn"
        decode: [base64, url]        # decode before matching; optional
        case_insensitive: true

      - name: "path-traversal"
        pattern: "\\.\\./"
        fields: ["path", "file_path"]
        action: block

Behavior:
- ``block`` rejects the call and logs a warning to the audit stream.
- ``warn`` lets the call through but logs the same warning.
- Block rules are evaluated before warn rules; the chain short-circuits on
  the first block.
- Values are NEVER logged — only ``filter_name``, ``tool_name``, ``field_name``.

Hardening (security review pre-checks):
- Patterns are re.compile()'d once at construction so a malformed pattern
  fails the manifest at startup, not at first call. ReDoS exposure is bounded
  primarily by the input-size cap below — Python's stdlib ``re`` has no native
  per-match timeout. Operator-supplied patterns are trusted; review them.
- Base64 decode results are capped at ``_MAX_DECODED_BYTES`` (64 KiB). Larger
  candidates are matched against the raw string only — the decoded form is
  skipped, not truncated, to avoid silent partial scans.

Auto-registered when ``argument_filters`` is present in the manifest.
"""

from __future__ import annotations

import base64
import re
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

import structlog

logger = structlog.get_logger("audit")

_MAX_DECODED_BYTES = 64 * 1024  # 64 KiB cap on base64-decoded content

Action = Literal["block", "warn"]
DecodeStep = Literal["base64", "urlsafe_base64", "url"]


@dataclass
class _CompiledRule:
    name: str
    pattern: re.Pattern[str]
    fields: list[str]  # ["*"] means all string fields
    action: Action
    decode: list[DecodeStep]


def _compile_rule(rule: dict[str, Any]) -> _CompiledRule:
    name = rule["name"]
    raw_pattern = rule["pattern"]
    flags = re.IGNORECASE if rule.get("case_insensitive") else 0
    try:
        compiled = re.compile(raw_pattern, flags)
    except re.error as e:
        raise ValueError(f"argument_filters[{name!r}].pattern is not a valid regex: {e}") from e
    fields = list(rule.get("fields", ["*"]))
    if not fields:
        raise ValueError(f"argument_filters[{name!r}].fields must not be empty")
    action = rule.get("action", "block")
    if action not in ("block", "warn"):
        raise ValueError(
            f"argument_filters[{name!r}].action must be 'block' or 'warn', got {action!r}"
        )
    decode = list(rule.get("decode", []))
    for step in decode:
        if step not in ("base64", "urlsafe_base64", "url"):
            raise ValueError(
                f"argument_filters[{name!r}].decode entry must be one of "
                f"('base64', 'urlsafe_base64', 'url'), got {step!r}"
            )
    return _CompiledRule(name=name, pattern=compiled, fields=fields, action=action, decode=decode)


def _b64_decode(value: str, urlsafe: bool) -> str | None:
    """Return decoded value or None if input would exceed cap or fails to decode."""
    # Reject candidates that would decode to >64 KiB before doing the work.
    # base64 inflates by ~4/3 → an N-char input decodes to ~3N/4 bytes.
    if (len(value) * 3) // 4 > _MAX_DECODED_BYTES:
        return None
    try:
        if urlsafe:
            # urlsafe_b64decode requires correct padding; pad up to a multiple of 4.
            padded = value + "=" * (-len(value) % 4)
            decoded = base64.urlsafe_b64decode(padded)
        else:
            decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error):
        return None
    if len(decoded) > _MAX_DECODED_BYTES:
        return None
    return decoded.decode("utf-8", errors="replace")


def _candidate_strings(value: str, decode_steps: list[DecodeStep]) -> list[str]:
    """Return [raw, *each successful decode of raw]. Decode failures are skipped."""
    candidates = [value]
    current = value
    for step in decode_steps:
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


def _field_matches(field_name: str, rule_fields: list[str]) -> bool:
    if "*" in rule_fields:
        return True
    return field_name in rule_fields


def _iter_string_fields(kwargs: dict[str, Any]) -> list[tuple[str, str]]:
    """Yield (field_name, string_value) for top-level string args.

    Nested structures aren't walked — argument filters target the visible
    argument surface declared by the upstream tool's inputSchema. Operators
    needing deep inspection should write a more specific rule pattern.
    """
    out: list[tuple[str, str]] = []
    for k, v in kwargs.items():
        if isinstance(v, str):
            out.append((k, v))
    return out


class ArgumentFilterMiddleware:
    """ToolCallMiddleware that pattern-matches against argument values.

    On a ``block`` match: raises ``ConfigError`` and logs a warning.
    On a ``warn`` match: logs a warning and lets the call through.

    Block rules are evaluated before warn rules across the rule list. Within a
    single rule, the first matching field short-circuits.
    """

    def __init__(self, rules: list[dict[str, Any]], agent_id: str) -> None:
        compiled = [_compile_rule(r) for r in rules]
        # Stable partition: blocks first (preserving original order), then warns.
        self._block_rules = [r for r in compiled if r.action == "block"]
        self._warn_rules = [r for r in compiled if r.action == "warn"]
        self._agent_id = agent_id

    def _scan(self, rule: _CompiledRule, fields: list[tuple[str, str]]) -> tuple[str, str] | None:
        """Return (field_name, candidate_label) of the first match or None."""
        for field_name, value in fields:
            if not _field_matches(field_name, rule.fields):
                continue
            for idx, candidate in enumerate(_candidate_strings(value, rule.decode)):
                if rule.pattern.search(candidate) is not None:
                    label = "raw" if idx == 0 else "decoded"
                    return field_name, label
        return None

    async def __call__(
        self,
        agent_ctx: Any,
        tool_name: str,
        kwargs: dict[str, Any],
        call_next: Callable[[], Any],
    ) -> Any:
        fields = _iter_string_fields(kwargs)
        if not fields:
            return await call_next()

        # Blocks first — short-circuit on the first hit so a downstream warn
        # cannot mask a block rejection in the audit log.
        for rule in self._block_rules:
            hit = self._scan(rule, fields)
            if hit is not None:
                field_name, candidate_label = hit
                logger.warning(
                    "argument_filter_blocked",
                    agent_id=self._agent_id,
                    tool=tool_name,
                    filter_name=rule.name,
                    field_name=field_name,
                    matched_on=candidate_label,
                )
                from ..exceptions import ConfigError

                # Generic message — rule name and field are already in the
                # structured audit log written above. Including them in the
                # agent-facing message would let an agent enumerate filter
                # configuration via probe-and-observe (audit L3).
                raise ConfigError(f"tool call to {tool_name!r} blocked by argument filter policy")

        # Warns are advisory — log every hit but don't short-circuit.
        for rule in self._warn_rules:
            hit = self._scan(rule, fields)
            if hit is not None:
                field_name, candidate_label = hit
                logger.warning(
                    "argument_filter_warning",
                    agent_id=self._agent_id,
                    tool=tool_name,
                    filter_name=rule.name,
                    field_name=field_name,
                    matched_on=candidate_label,
                )

        return await call_next()
