#!/bin/bash
# Template: scoped-mcp launcher with per-session log isolation.
#
# Copy to a location on PATH (e.g. ~/scripts/run-scoped-mcp.sh) and adjust
# MANIFEST, AUDIT_DIR, and OPS_DIR for your deployment.
#
# Why a launcher: pooled agents (e.g. two concurrent sessions of the same agent
# type) interleave writes if they share one --audit-log path. Each session gets
# its own audit-<pid>-<ts>.jsonl / ops-<pid>-<ts>.jsonl so log consumers can
# correlate all events from a single session without collision.
#
# AGENT_ID / AGENT_TYPE come from the caller's environment (e.g. Claude Code
# settings.json env block). AGENT_TYPE is required.
set -euo pipefail

: "${AGENT_TYPE:?AGENT_TYPE not set}"

MANIFEST="/path/to/manifests/${AGENT_TYPE}-agent.yml"
AUDIT_DIR="/path/to/audit/${AGENT_TYPE}"
OPS_DIR="/path/to/ops/${AGENT_TYPE}"

mkdir -p "$AUDIT_DIR" "$OPS_DIR"

SID="$$-$(date +%s)"

exec /path/to/venv/bin/scoped-mcp run \
  --manifest "$MANIFEST" \
  --audit-log "${AUDIT_DIR}/audit-${SID}.jsonl" \
  --ops-log "${OPS_DIR}/ops-${SID}.jsonl"
