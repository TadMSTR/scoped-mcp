"""Tests for contrib/response_filter.py — response content scanning and redaction."""

from __future__ import annotations

import pytest
from mcp.types import EmbeddedResource, ImageContent, TextContent, TextResourceContents

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


# ── MCP content blocks (vikunja#1070) ─────────────────────────────────────────
# mcp_proxy now returns content blocks unchanged when a result carries an image, so the
# text inside those blocks must not slip past the filter.


def test_redact_inside_text_content_block() -> None:
    rf = _make_filter([{"name": "r1", "pattern": "ghp_[A-Za-z0-9]{36}", "action": "redact"}])
    token = "ghp_" + "A" * 36
    image = ImageContent(type="image", data="aGVsbG8=", mimeType="image/png")
    result = rf.filter_response(
        [image, TextContent(type="text", text=f"link {token}")], "get_panel_image", "agent-1"
    )
    assert [type(b) for b in result] == [ImageContent, TextContent]
    assert result[0] == image
    assert result[1].text == "link [REDACTED]"


def test_block_inside_text_content_block() -> None:
    rf = _make_filter([{"name": "b1", "pattern": "secret", "action": "block"}])
    with pytest.raises(ConfigError, match="blocked by response filter policy"):
        rf.filter_response([TextContent(type="text", text="a secret")], "t", "agent-1")


def test_redact_inside_embedded_text_resource() -> None:
    rf = _make_filter([{"name": "r1", "pattern": "secret", "action": "redact"}])
    block = EmbeddedResource(
        type="resource",
        resource=TextResourceContents(uri="file:///x", text="a secret", mimeType="text/plain"),
    )
    result = rf.filter_response([block], "t", "agent-1")
    assert result[0].resource.text == "a [REDACTED]"
    assert block.resource.text == "a secret"  # original not mutated


def test_block_when_redaction_leaves_an_invalid_block() -> None:
    """A URI redacted whole no longer validates: block rather than forward it unfiltered."""
    from mcp.types import ResourceLink

    rf = _make_filter([{"name": "r1", "pattern": "^.*$", "action": "redact"}])
    link = ResourceLink(type="resource_link", uri="https://x/y", name="n")
    with pytest.raises(ConfigError, match="blocked by response filter policy"):
        rf.filter_response([link], "t", "agent-1")


def test_binary_typed_blob_is_neither_scanned_nor_rewritten() -> None:
    import base64

    from mcp.types import BlobResourceContents

    token = "ghp_" + "A" * 36
    blob = base64.b64encode(token.encode()).decode()
    rf = _make_filter(
        [{"name": "r1", "pattern": "ghp_[A-Za-z0-9]{36}", "action": "redact", "decode": ["base64"]}]
    )
    block = EmbeddedResource(
        type="resource",
        resource=BlobResourceContents(uri="file:///x.png", blob=blob, mimeType="image/png"),
    )
    result = rf.filter_response([block], "t", "agent-1")
    assert result[0].resource.blob == blob


# ── Round 2 (audit R2-01, R2-02) ──────────────────────────────────────────────

_R2_TOKEN = "ghp_" + "B" * 36
_R2_RULE = {
    "name": "response-credential-leak",
    "pattern": "ghp_[A-Za-z0-9]{36}",
    "action": "redact",
    "decode": ["base64"],
}


def _b64(text: str) -> str:
    import base64

    return base64.b64encode(text.encode()).decode()


def test_redact_decoded_only_match_replaces_the_whole_value() -> None:
    """R2-01: the raw string has nothing to substitute, so it used to go out unchanged."""
    rf = _make_filter([_R2_RULE])
    encoded = _b64(f"x {_R2_TOKEN}")
    assert rf.filter_response(encoded, "t", "agent-1") == "[REDACTED]"
    assert rf.filter_response({"k": encoded}, "t", "agent-1") == {"k": "[REDACTED]"}
    block = rf.filter_response([TextContent(type="text", text=encoded)], "t", "agent-1")[0]
    assert block.text == "[REDACTED]"


def test_redact_raw_match_still_substitutes_in_place() -> None:
    rf = _make_filter([_R2_RULE])
    assert rf.filter_response(f"a {_R2_TOKEN} b", "t", "agent-1") == "a [REDACTED] b"


def test_redact_no_match_leaves_base64_alone() -> None:
    rf = _make_filter([_R2_RULE])
    encoded = _b64("nothing secret here")
    assert rf.filter_response(encoded, "t", "agent-1") == encoded


def _text_blob(blob: str) -> EmbeddedResource:
    from mcp.types import BlobResourceContents

    return EmbeddedResource(
        type="resource",
        resource=BlobResourceContents(uri="file:///x.log", blob=blob, mimeType="text/plain"),
    )


def test_text_blob_over_64k_is_scanned() -> None:
    """R2-02: a 70 KB text blob used to pass unscanned under the shared 64 KiB cap."""
    rf = _make_filter([_R2_RULE])
    with pytest.raises(ConfigError, match="blocked by response filter policy"):
        rf.filter_response([_text_blob(_b64("a" * 70_000 + _R2_TOKEN))], "t", "agent-1")


def test_clean_text_blob_over_64k_passes() -> None:
    rf = _make_filter([_R2_RULE])
    blob = _b64("a" * 70_000)
    assert rf.filter_response([_text_blob(blob)], "t", "agent-1")[0].resource.blob == blob


@pytest.mark.parametrize(
    "blob",
    [_b64("a" * (4 * 1024 * 1024 + 1)), "not base64 at all!"],
    ids=["over-text-blob-cap", "malformed"],
)
def test_unscannable_text_blob_blocks(blob: str) -> None:
    rf = _make_filter([_R2_RULE])
    with pytest.raises(ConfigError, match="blocked by response filter policy"):
        rf.filter_response([_text_blob(blob)], "t", "agent-1")
