-- Migration 0001 — agent session registry (v1, full schema)
--
-- Target: agent-postgres (127.0.0.1:5433), dedicated least-privilege registry role.
-- Applied by: sysadmin (Phase A of hitl-approval-flow-2026-07 / SMCP-14).
--
-- This is a GENERAL agent session registry, not HITL-only. HITL is the first
-- consumer (`hitl_approvals`); the remaining tables are designed-in and wired
-- incrementally by later builds. The full v1 schema is applied in one migration
-- to avoid a re-migration when those consumers land.
--
-- Idempotent: safe to re-run. All objects use IF NOT EXISTS; the whole file
-- runs inside a single transaction so a partial apply cannot leave the schema
-- half-built.

BEGIN;

-- ---------------------------------------------------------------------------
-- P1: session registry — HITL approval routing needs this.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
    session_id      TEXT PRIMARY KEY,          -- Claude Code JSONL session UUID
    agent_id        TEXT NOT NULL,
    transport       TEXT NOT NULL,             -- cloudcli | matrix | clonepool | headless
    room_id         TEXT,
    project_dir     TEXT,
    scoped_mcp_url  TEXT,                       -- per-agent scoped-mcp base URL (approve routing)
    status          TEXT NOT NULL DEFAULT 'active',
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- P1: HITL audit record. The plaintext OTP lives ONLY in Dragonfly and is
-- never persisted here — only a hash, for audit correlation.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS hitl_approvals (
    approval_id     TEXT PRIMARY KEY,           -- {agent_id}.{uuid12}
    session_id      TEXT REFERENCES sessions(session_id),
    agent_id        TEXT NOT NULL,
    tool_name       TEXT NOT NULL,
    token_hash      TEXT,                        -- sha256 of the OTP, audit only
    state           TEXT NOT NULL,               -- pending | approved | denied | consumed | expired
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at     TIMESTAMPTZ,
    ttl_seconds     INTEGER
);

-- ---------------------------------------------------------------------------
-- P2: task-queue linkage (no writer yet; wired by a later build).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS session_tasks (
    id              BIGSERIAL PRIMARY KEY,
    session_id      TEXT REFERENCES sessions(session_id),
    task_id         TEXT NOT NULL,               -- task-queue-mcp task id
    role            TEXT NOT NULL,               -- parent | child
    build_name      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- P2: token / cost accounting rollup (no writer yet).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS session_usage (
    id                  BIGSERIAL PRIMARY KEY,
    session_id          TEXT REFERENCES sessions(session_id),
    model               TEXT,
    input_tokens        BIGINT,
    output_tokens       BIGINT,
    cache_read_tokens   BIGINT,
    cache_write_tokens  BIGINT,
    cost_usd            NUMERIC(12,6),
    langfuse_session_id TEXT,
    recorded_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- P3: memory provenance for agent-authored notes/episodes (no writer yet).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS memory_artifacts (
    id              BIGSERIAL PRIMARY KEY,
    session_id      TEXT REFERENCES sessions(session_id),
    artifact_type   TEXT NOT NULL,               -- note | graphiti_episode | distilled
    ref             TEXT NOT NULL,               -- file path or episode UUID
    tier            TEXT,                         -- session | working | distilled
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_hitl_agent_state ON hitl_approvals(agent_id, state);
CREATE INDEX IF NOT EXISTS idx_sessions_agent   ON sessions(agent_id, status);

-- ---------------------------------------------------------------------------
-- Migration bookkeeping.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     TEXT PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO schema_migrations (version)
VALUES ('0001_agent_session_registry')
ON CONFLICT (version) DO NOTHING;

COMMIT;
