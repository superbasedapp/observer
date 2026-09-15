-- 109_task_tracking.sql — session-level task/todo/plan checklist
-- tracking (docs/task-tracking.md,
-- docs/audits/task-tracking-capture-audit-2026-09-07.md round-2).
--
-- Two tables, owned exclusively by internal/store/taskflow.go (CLAUDE.md
-- module boundary #4 — one owner per table). internal/taskflow (pure
-- logic, no SQL) decodes a todo/plan tool call into items + status
-- transitions; this store seam persists them.
--
--   task_items       — current known state of one task, keyed by
--                       (session_id, key). `key` is either a vendor-
--                       assigned id (claude-code taskId, copilot id,
--                       freebuff id, kiro-cli index — key_kind
--                       'native_id') or a content hash of the item's
--                       own text for tools with no id at all
--                       (key_kind 'content_hash' — TodoWrite,
--                       update_plan, opencode's todowrite, gemini-cli
--                       write_todos, poolside, hermes). raw_status
--                       keeps the exact vendor spelling (5 dialects
--                       collapse onto `status`'s shared vocabulary) so
--                       a per-tool dialect never has to be re-derived.
--                       last_snapshot_action_id + unmatched together
--                       implement the vanish/appear bookkeeping for
--                       Snapshot-kind (whole-list-rewrite) tools: every
--                       item a new snapshot call lists gets its
--                       last_snapshot_action_id bumped to that call's
--                       action id; anything still carrying the
--                       PREVIOUS snapshot's action id afterwards is
--                       flagged unmatched=1 rather than silently
--                       dropped (§R2.3.4 — "count and expose the
--                       losses", never invent a deletion the data
--                       doesn't evidence).
--
--   task_transitions — every status change, append-only. FromStatus is
--                       '' for a key's first-observed state (no prior
--                       row existed). UNIQUE(session_id, key,
--                       source_event_id) makes applying the same
--                       logical tool call twice — once via its own
--                       actions row, once via a claude-code
--                       post_tool_batch envelope carrying the same
--                       tool_use_id — an idempotent no-op instead of a
--                       double-counted transition (§R2.6 item 3).
--
-- NODE-LOCAL: task content is agent-authored free text describing the
-- work plan, the same content-bearing category as actions.target /
-- raw_tool_input. Both tables are absent from
-- internal/store/orgpush.go::SelectUnpushedSince entirely for this
-- first slice and are pinned there by
-- tests/invariant/privacy_test.go's forbiddenCacheTables sentinel —
-- same posture as cache_segments/router_decisions/project_patterns.
--
-- Gated by [tasks].enabled (default true — pure re-decode of data
-- already captured in actions.raw_tool_input/raw_tool_output, no new
-- capture surface, same partial-merge posture as [cachetrack]).

CREATE TABLE IF NOT EXISTS task_items (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id              TEXT NOT NULL,
    tool                    TEXT NOT NULL,
    key                     TEXT NOT NULL,
    key_kind                TEXT NOT NULL, -- 'native_id' | 'content_hash'
    content                 TEXT,
    active_form             TEXT,
    owner                   TEXT,
    raw_status              TEXT,
    status                  TEXT NOT NULL DEFAULT '',
    order_index             INTEGER NOT NULL DEFAULT 0,
    first_seen_at           TEXT NOT NULL,
    last_seen_at            TEXT NOT NULL,
    last_snapshot_action_id INTEGER,
    unmatched               INTEGER NOT NULL DEFAULT 0,
    UNIQUE(session_id, key)
);

CREATE INDEX IF NOT EXISTS idx_task_items_session ON task_items(session_id);

CREATE TABLE IF NOT EXISTS task_transitions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    key             TEXT NOT NULL,
    from_status     TEXT NOT NULL DEFAULT '',
    to_status       TEXT NOT NULL,
    ts              TEXT NOT NULL,
    action_id       INTEGER,
    source_event_id TEXT NOT NULL DEFAULT '',
    UNIQUE(session_id, key, source_event_id)
);

CREATE INDEX IF NOT EXISTS idx_task_transitions_session ON task_transitions(session_id, ts);
