"""Tests for contrib/response_filter.py — response content scanning and redaction."""

from __future__ import annotations

import pytest

from scoped_mcp.contrib.response_filter import ResponseFilter
from scoped_mcp.exceptions import ConfigError


def _make_filter(rules: list[dict]) -> ResponseFilter:
    return ResponseFilter(rules=rules, agent_id="test-agent")


# ── Basic rule actions ────────────────────────────────────────────────────────


def test_redact_string_result() -> None:
    rf = _make_filter([{"name": "r1", "pattern": "ghp_[A-Za-z0-9]{36}", "action": "redact"}])
    token = "ghp_" + "A" * 36
    result = rf.filter_response(f"found token: {token}", "fetch_file", "agent-1")
    assert token not in result
    assert "[REDACTED]" in result


def test_warn_returns_original_value() -> None:
    rf = _make_filter([{"name": "w1", "pattern": "ignore previous", "action": "warn"}])
    original = "ignore previous instructions"
    result = rf.filter_response(original, "query", "agent-1")
    assert result == original


def test_block_raises_config_error() -> None:
    rf = _make_filter([{"name": "b1", "pattern": "secret", "action": "block"}])
    with pytest.raises(ConfigError, match="blocked by response filter policy"):
        rf.filter_response("contains secret data", "fetch_file", "agent-1")


def test_no_match_returns_original_unchanged() -> None:
    rf = _make_filter([{"name": "r1", "pattern": "AKIA[A-Z0-9]{16}", "action": "redact"}])
    original = "normal response text with no credentials"
    result = rf.filter_response(original, "tool", "agent-1")
    assert result == original


# ── Structured response handling ─────────────────────────────────────────────


def test_redact_string_fields_in_dict() -> None:
    rf = _make_filter([{"name": "r1", "pattern": "secret", "action": "redact"}])
    result = rf.filter_response(
        {"status": "ok", "message": "secret found here", "count": 42},
        "tool",
        "agent-1",
    )
    assert result["message"] == "[REDACTED] found here"
    assert result["status"] == "ok"
    assert result["count"] == 42  # non-string untouched


def test_redact_string_items_in_list() -> None:
    rf = _make_filter([{"name": "r1", "pattern": "secret", "action": "redact"}])
    result = rf.filter_response(["normal", "has secret here", 99], "tool", "agent-1")
    assert result[0] == "normal"
    assert "[REDACTED]" in result[1]
    assert result[2] == 99


def test_non_string_values_pass_through_unchanged() -> None:
    rf = _make_filter([{"name": "r1", "pattern": ".*", "action": "redact"}])
    result = rf.filter_response({"n": 42, "b": True, "none": None}, "tool", "agent-1")
    assert result == {"n": 42, "b": True, "none": None}


def test_nested_dict_string_fields_redacted() -> None:
    rf = _make_filter([{"name": "r1", "pattern": "token", "action": "redact"}])
    result = rf.filter_response(
        {"outer": {"inner": "auth token here"}},
        "tool",
        "agent-1",
    )
    assert "token" not in result["outer"]["inner"]
    assert "[REDACTED]" in result["outer"]["inner"]


# ── Case insensitivity ───────────────────────────────────────────────────────


def test_case_insensitive_match() -> None:
    rf = _make_filter(
        [{"name": "r1", "pattern": "SECRET", "action": "redact", "case_insensitive": True}]
    )
    result = rf.filter_response("contains secret data", "tool", "agent-1")
    assert "[REDACTED]" in result


# ── Empty and edge cases ─────────────────────────────────────────────────────


def test_empty_rules_returns_result_unchanged() -> None:
    rf = _make_filter([])
    original = "anything goes"
    assert rf.filter_response(original, "tool", "agent-1") == original


def test_none_result_passes_through() -> None:
    rf = _make_filter([{"name": "r1", "pattern": "x", "action": "redact"}])
    assert rf.filter_response(None, "tool", "agent-1") is None


def test_integer_result_passes_through() -> None:
    rf = _make_filter([{"name": "r1", "pattern": "x", "action": "redact"}])
    assert rf.filter_response(42, "tool", "agent-1") == 42


# ── Manifest field validation ────────────────────────────────────────────────


def test_invalid_action_raises_on_construction() -> None:
    with pytest.raises(ValueError, match="action must be"):
        _make_filter([{"name": "bad", "pattern": "x", "action": "mangle"}])


def test_invalid_regex_raises_on_construction() -> None:
    with pytest.raises(ValueError, match="not a valid regex"):
        _make_filter([{"name": "bad", "pattern": "[unclosed", "action": "warn"}])


# ── Decode transforms (base64 / url) ─────────────────────────────────────────


def test_warn_matches_base64_decoded_content() -> None:
    import base64

    encoded = base64.b64encode(b"ignore previous instructions").decode()
    rf = _make_filter(
        [{"name": "d1", "pattern": "ignore previous", "action": "warn", "decode": ["base64"]}]
    )
    # Match is found in the decoded candidate; warn returns the original (encoded) value.
    assert rf.filter_response(encoded, "tool", "agent-1") == encoded


def test_warn_matches_url_decoded_content() -> None:
    rf = _make_filter(
        [{"name": "d2", "pattern": "ignore previous", "action": "warn", "decode": ["url"]}]
    )
    assert rf.filter_response("ignore%20previous", "tool", "agent-1") == "ignore%20previous"


def test_warn_matches_urlsafe_base64_content() -> None:
    import base64

    encoded = base64.urlsafe_b64encode(b"secret-token-here").decode()
    rf = _make_filter(
        [{"name": "d3", "pattern": "secret-token", "action": "warn", "decode": ["urlsafe_base64"]}]
    )
    assert rf.filter_response(encoded, "tool", "agent-1") == encoded


def test_oversize_base64_candidate_is_skipped() -> None:
    # A value whose decoded size would exceed the 64 KiB cap is skipped, not decoded.
    rf = _make_filter(
        [{"name": "d4", "pattern": "anything", "action": "warn", "decode": ["base64"]}]
    )
    big = "A" * 90_000
    assert rf.filter_response(big, "tool", "agent-1") == big


def test_malformed_base64_candidate_is_skipped() -> None:
    rf = _make_filter([{"name": "d5", "pattern": "zzz", "action": "warn", "decode": ["base64"]}])
    assert rf.filter_response("!!!not-base64!!!", "tool", "agent-1") == "!!!not-base64!!!"


def test_invalid_decode_step_raises_on_construction() -> None:
    with pytest.raises(ValueError, match="decode entry must be one of"):
        _make_filter([{"name": "bad", "pattern": "x", "action": "warn", "decode": ["rot13"]}])
