"""Regression guard (SMCP-4): manifest schema must accept workspace_access.

Background: scoped-mcp 1.3.2 was branched from a stale main and on merge silently
reverted commit 57fde89, flipping the top-level ``Manifest`` model back to
``extra="forbid"`` without modeling ``workspace_access``. Every agent manifest carries a
``workspace_access`` block, so 1.3.2 rejected all of them
(``ValidationError: workspace_access extra_forbidden``) and broke scoped-mcp connections
forge-wide once the venv upgraded.

These tests pin two invariants:
  1. A manifest carrying a ``workspace_access`` block validates — the CI-runnable guard
     that a future stale merge cannot silently re-break.
  2. ``extra="forbid"`` is preserved, so genuinely unknown top-level fields are still
     rejected (shadowing-attack protection).

The live-manifest test validates the real ``/etc/forge/manifests/*-agent.yml`` files
structurally (``model_validate`` on parsed YAML, no env expansion) and is skipped when
the directory is absent — e.g. in CI.
"""

from __future__ import annotations

import glob
import os
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from scoped_mcp.manifest import Manifest

# The root-owned deployed copies — the files the running processes actually load
# (run-scoped-mcp-http.sh passes --manifest /etc/forge/manifests/<agent>-agent.yml).
# Deliberately NOT ~/.claude/manifests: that is a symlink into a git working tree,
# so this test would validate whatever branch happened to be checked out rather
# than what is deployed. vikunja#353.
_LIVE_GLOB = "/etc/forge/manifests/*-agent.yml"
_LIVE_MANIFESTS = sorted(glob.glob(_LIVE_GLOB))


def test_manifest_with_workspace_access_validates() -> None:
    """The core regression guard: a workspace_access block must be accepted (runs in CI)."""
    manifest = Manifest.model_validate(
        {
            "agent_type": "test",
            "modules": {"ntfy": {}},
            "workspace_access": [
                {
                    "path": "~/repos/gitea/agent-platform-agents/",
                    "access": "readwrite",
                    "git_backed": True,
                    "branch_required": False,
                },
                {"path": "~/.claude/comms/", "access": "readonly"},
            ],
        }
    )
    assert manifest.workspace_access is not None
    assert manifest.workspace_access[0].access == "readwrite"
    assert manifest.workspace_access[0].git_backed is True
    # git_backed / branch_required default to False when omitted
    assert manifest.workspace_access[1].git_backed is False
    assert manifest.workspace_access[1].branch_required is False


def test_workspace_access_rejects_unknown_access_value() -> None:
    """access is a closed enum — typos must fail rather than silently pass."""
    with pytest.raises(ValidationError):
        Manifest.model_validate(
            {
                "agent_type": "test",
                "modules": {"ntfy": {}},
                "workspace_access": [{"path": "~/x", "access": "write"}],
            }
        )


def test_unknown_top_level_field_still_rejected() -> None:
    """extra="forbid" preserved — modeling workspace_access must not reopen the model."""
    with pytest.raises(ValidationError):
        Manifest.model_validate(
            {
                "agent_type": "test",
                "modules": {"ntfy": {}},
                "unknown_field": "bad",
            }
        )


@pytest.mark.skipif(not _LIVE_MANIFESTS, reason="no live agent manifests on this host")
@pytest.mark.parametrize("path", _LIVE_MANIFESTS, ids=lambda p: os.path.basename(p))
def test_live_agent_manifest_validates(path: str) -> None:
    """Every real agent manifest validates structurally (no env expansion, schema only)."""
    data = yaml.safe_load(Path(path).read_text())
    Manifest.model_validate(data)
