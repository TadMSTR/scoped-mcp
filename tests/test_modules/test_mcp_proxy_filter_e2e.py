"""End to end: upstream FastMCP -> mcp_proxy -> @audited response filter -> FastMCP -> agent.

The proxy forwards content blocks unchanged when a result carries a non-text block
(vikunja#1070). These tests assert what an agent receives with the response filter on,
not what ``_filter_value`` returns for hand-built input, so they pin the filter on the
path production actually runs (audit scoped-mcp-proxy-content-1070, F-01/F-02/F-03/F-06).
"""

from __future__ import annotations

import asyncio
import base64
from typing import Any
from unittest.mock import patch

import pytest
from fastmcp import Client as FastMCPClient
from fastmcp import FastMCP
from fastmcp.tools.tool import ToolResult
from mcp.types import (
    BlobResourceContents,
    EmbeddedResource,
    ImageContent,
    ResourceLink,
    TextContent,
    TextResourceContents,
)
from pydantic import BaseModel

from scoped_mcp.audit import audited, configure_audit
from scoped_mcp.contrib.response_filter import ResponseFilter
from scoped_mcp.identity import AgentContext
from scoped_mcp.modules.mcp_proxy import McpProxyModule

TOKEN = "ghp_" + "A1b2C3d4E5" * 3 + "F6g7H8"  # 36 chars after the prefix
assert len(TOKEN) == 40

# The credential rule as forge manifests carry it: redact, with a base64 decode step.
_CREDENTIAL_RULE = {
    "name": "response-credential-leak",
    "pattern": "(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|AKIA[A-Z0-9]{16})",
    "action": "redact",
    "decode": ["base64"],
}

# Binary-looking image payload that also contains the token's bytes. It must arrive intact:
# the filter must never rewrite base64 image data.
_PNG_WITH_TOKEN = base64.b64encode(
    b"\x89PNG\r\n\x1a\n" + TOKEN.encode() + bytes(range(256))
).decode()

_B64_TOKEN = base64.b64encode(f"token {TOKEN}".encode()).decode()
_DUAL_SMALL = _B64_TOKEN
# Decodes to ~70 KB: over the 64 KiB nested-decode cap, under the 4 MiB text-blob cap.
_DUAL_LARGE = base64.b64encode(("a" * 70_000 + TOKEN).encode()).decode()
_DUAL_LARGE_CLEAN = base64.b64encode(("a" * 70_000).encode()).decode()


class Secret(BaseModel):
    token: str
    note: str


def _upstream() -> FastMCP:
    up = FastMCP("upstream")

    @up.tool
    def mixed() -> ToolResult:
        return ToolResult(
            content=[
                ImageContent(
                    type="image",
                    data=_PNG_WITH_TOKEN,
                    mimeType="image/png",
                    _meta={"source": f"meta {TOKEN}"},
                    extra_field=f"extra {TOKEN}",
                ),
                TextContent(type="text", text=f"deeplink {TOKEN}"),
                ResourceLink(
                    type="resource_link",
                    uri=f"https://grafana.example/d/{TOKEN}",
                    name=f"name {TOKEN}",
                    title=f"title {TOKEN}",
                    description=f"description {TOKEN}",
                ),
            ]
        )

    @up.tool
    def text_blob() -> ToolResult:
        return ToolResult(
            content=[
                ImageContent(type="image", data=_PNG_WITH_TOKEN, mimeType="image/png"),
                EmbeddedResource(
                    type="resource",
                    resource=BlobResourceContents(
                        uri="file:///report.txt",
                        mimeType="text/plain",
                        blob=base64.b64encode(f"token {TOKEN}".encode()).decode(),
                    ),
                ),
            ]
        )

    @up.tool
    def encoded() -> ToolResult:
        # R2-01: a base64-encoded credential as plain text.
        return ToolResult(
            content=[
                ImageContent(type="image", data=_PNG_WITH_TOKEN, mimeType="image/png"),
                TextContent(type="text", text=_B64_TOKEN),
            ]
        )

    def _dual(blob: str) -> ToolResult:
        # A resource carrying both `blob` and `text` is not valid MCP; mcp.types parses it as
        # TextResourceContents with `blob` as an extra field (R2-01, R3-01).
        return ToolResult(
            content=[
                ImageContent(type="image", data=_PNG_WITH_TOKEN, mimeType="image/png"),
                EmbeddedResource(
                    type="resource",
                    resource=TextResourceContents(
                        uri="file:///dual.txt", mimeType="text/plain", text="", blob=blob
                    ),
                ),
            ]
        )

    @up.tool
    def dual_small() -> ToolResult:
        return _dual(_DUAL_SMALL)

    @up.tool
    def dual_large() -> ToolResult:
        return _dual(_DUAL_LARGE)

    @up.tool
    def dual_large_clean() -> ToolResult:
        return _dual(_DUAL_LARGE_CLEAN)

    @up.tool
    def typed() -> Secret:
        return Secret(token=TOKEN, note="model-typed output")

    return up


def _call(tool: str) -> Any:
    """Build the proxy against a live upstream, wrap it as the registry does, call it."""
    up = _upstream()
    with patch("scoped_mcp.modules.mcp_proxy.Client", lambda *_a, **_k: FastMCPClient(up)):
        mod = McpProxyModule(
            agent_ctx=AgentContext(agent_id="test-agent", agent_type="test"),
            credentials={},
            config={"url": "http://127.0.0.1:8485/mcp"},
        )
        method = next(m for m in mod.get_tool_methods(mode=None) if m.__name__ == tool)
        app = FastMCP("broker")
        app.tool(audited(f"upstream_{tool}")(method), name=tool)

        async def run():
            async with FastMCPClient(app) as client:
                return await client.call_tool(tool, {}, raise_on_error=False)

        configure_audit(response_filter=ResponseFilter([_CREDENTIAL_RULE], agent_id="test-agent"))
        try:
            return asyncio.run(run())
        finally:
            configure_audit(response_filter=None)


def _wire(result: Any) -> str:
    """Everything the agent receives, serialised, for a leak check."""
    return "".join(block.model_dump_json(by_alias=True) for block in result.content) + str(
        result.structured_content
    )


def test_mixed_result_redacts_every_string_field_and_keeps_the_image():
    result = _call("mixed")
    assert not result.is_error

    assert [type(b) for b in result.content] == [ImageContent, TextContent, ResourceLink]
    image, text, link = result.content

    # The image payload is untouched, byte for byte.
    assert image.mimeType == "image/png"
    assert image.data == _PNG_WITH_TOKEN

    # F-01: every string on every block went through the filter.
    assert image.meta == {"source": "meta [REDACTED]"}
    assert image.model_extra["extra_field"] == "extra [REDACTED]"
    assert text.text == "deeplink [REDACTED]"
    assert link.name == "name [REDACTED]"
    assert link.title == "title [REDACTED]"
    assert link.description == "description [REDACTED]"
    assert TOKEN not in str(link.uri)

    # And nothing anywhere else on the wire carries it, outside the image payload.
    assert TOKEN not in _wire(result).replace(_PNG_WITH_TOKEN, "")


def test_text_typed_blob_with_a_credential_blocks_the_response():
    """F-02: a text/plain blob is decoded and scanned; redact escalates to block."""
    result = _call("text_blob")
    assert result.is_error
    assert "blocked by response filter policy" in result.content[0].text
    assert TOKEN not in _wire(result)
    assert base64.b64encode(f"token {TOKEN}".encode()).decode() not in _wire(result)


def test_model_typed_structured_output_is_redacted():
    """F-03: a model-typed upstream output used to reach the agent as an unscanned object."""
    result = _call("typed")
    assert not result.is_error
    assert TOKEN not in _wire(result)
    assert "[REDACTED]" in _wire(result)
    assert "model-typed output" in _wire(result)


def test_base64_encoded_credential_is_redacted_not_just_logged():
    """R2-01: decode-only matches were logged as redacted and forwarded unchanged."""
    result = _call("encoded")
    assert not result.is_error
    assert [type(b) for b in result.content] == [ImageContent, TextContent]
    assert result.content[1].text == "[REDACTED]"
    assert _B64_TOKEN not in _wire(result)
    assert result.content[0].data == _PNG_WITH_TOKEN


@pytest.mark.parametrize(
    ("tool", "blob"),
    [("dual_small", _DUAL_SMALL), ("dual_large", _DUAL_LARGE)],
    ids=["small", "over-64k"],
)
def test_dual_blob_text_resource_is_scanned_like_a_blob(tool, blob):
    """R3-01: a `blob` riding as an extra field gets the text-blob scan, at any size.

    Over 64 KiB it used to skip the nested decode and go out unscanned and unlogged.
    """
    result = _call(tool)
    assert result.is_error
    assert "blocked by response filter policy" in result.content[0].text
    assert blob not in _wire(result)


def test_clean_large_dual_resource_passes_with_its_blob_intact():
    result = _call("dual_large_clean")
    assert not result.is_error
    assert result.content[1].resource.model_extra["blob"] == _DUAL_LARGE_CLEAN


_LEAKS = {
    "mixed": TOKEN,
    "text_blob": _B64_TOKEN,
    "typed": TOKEN,
    "encoded": _B64_TOKEN,
    "dual_small": _DUAL_SMALL,
    "dual_large": _DUAL_LARGE,
}


@pytest.mark.parametrize("tool", sorted(_LEAKS))
def test_filter_off_forwards_unchanged(tool):
    """Control: with no filter the token does reach the agent, so the tests above can fail."""
    up = _upstream()
    with patch("scoped_mcp.modules.mcp_proxy.Client", lambda *_a, **_k: FastMCPClient(up)):
        mod = McpProxyModule(
            agent_ctx=AgentContext(agent_id="test-agent", agent_type="test"),
            credentials={},
            config={"url": "http://127.0.0.1:8485/mcp"},
        )
        method = next(m for m in mod.get_tool_methods(mode=None) if m.__name__ == tool)
        app = FastMCP("broker")
        app.tool(audited(f"upstream_{tool}")(method), name=tool)

        async def run():
            async with FastMCPClient(app) as client:
                return await client.call_tool(tool, {}, raise_on_error=False)

        configure_audit(response_filter=None)
        result = asyncio.run(run())

    assert not result.is_error
    wire = _wire(result).replace(_PNG_WITH_TOKEN, "")
    assert _LEAKS[tool] in wire
