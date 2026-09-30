-- 143_spend_verdicts.sql - the node's STORED proxy/transcript dedup verdicts
-- (lane R2-ONERULE, docs/plans/post-agent-access-backlog-tracker-2026-09-27.md
-- item 11 follow-ups). The node mirror of the org's server migration 179.
--
-- WHY. A session's spend is ONE rule, internal/sessionmsg.Derive: the node
-- session header, both engines' Messages tabs and the org drawer run it over
-- the session's rows. The node's WINDOWED surfaces (the cost engine behind
-- Cost / Analysis / reports / budget card / live / statusline, the guard's
-- budget windows, the predictor's cross-session prior) sum api_turns ∪
-- token_usage across many sessions, where Derive cannot run per row in SQL.
-- Until now the cost engine re-ran Derive in Go over the rows of ITS OWN
-- window (so a session straddling the window edge was judged on half its
-- rows, and the load carried every column Derive reads - ~1.8x slower per
-- Analysis panel), and the guard kept a per-session MAX(proxy, transcript)
-- rule of its own. Now Derive runs once per session whenever its rows change
-- and records its decisions here, exactly as the org does at ingest, and the
-- windowed surfaces apply them in SQL and sum the ordinary way.
--
-- WHAT IS STORED. Only the exceptions:
--   spend_verdict_token  one row per token_usage row Derive does NOT count (a
--                        proxy row's twin, a request-id duplicate, a paired
--                        output-only shadow row, or a row the
--                        session-cumulative reconciliation dropped). shadow = 1
--                        marks the output-only shadow pairing - the one reason
--                        a transcript-only read (cost --source jsonl) also
--                        applies, since it names no proxy row.
--   spend_verdict_proxy  one row per api_turns row whose contribution differs
--                        from its stored figures: a twinned row carries its
--                        transcript twin's visible output + reasoning and, if
--                        the twin is fast, inherits the fast tier; a row the
--                        session-cumulative reconciliation dropped has
--                        counted = 0.
-- A token_usage row with no verdict counts; an api_turns row with no verdict
-- counts as stored. Rows outside every session (an empty session_id) are
-- outside Derive's domain and always count.
--
-- FRESHNESS. The writers of api_turns / token_usage are many (store seams,
-- the proxy, `observer backfill` SQL, dedup migrations, retention), so the
-- change marker is a TRIGGER on each - the one seam every write passes
-- through, present or future (migration 140's precedent). A trigger queues
-- with INSERT ... WHERE NOT EXISTS, never INSERT OR IGNORE: SQLite replaces a
-- trigger statement's conflict clause with the firing statement's, so an
-- UPSERT on sessions / token_usage would turn OR IGNORE back into ABORT. A trigger only
-- queues the session id in spend_verdict_dirty; the ONE writer of the verdict
-- tables, internal/spendverdict.Refresh, re-derives queued sessions - from
-- the daemon's ticker and before every windowed read - each inside one write
-- transaction that also clears its queue entry, so SQLite's single writer
-- guarantees a row committed after the clear re-queues the session.
-- spend_verdict_state.rule_version records the sessionmsg rule the stored
-- verdicts were computed with; Refresh re-queues every candidate session once
-- when it is behind (spendverdict.RuleVersion), including on first run after
-- this migration. rev bumps on every verdict write (the cost engine's raw-row
-- cache fingerprints it).
--
-- NODE-LOCAL: derived numbers only, never selected onto the org-push wire
-- (the privacy sentinel pins all four names out of internal/store/orgpush.go).
-- The org derives its own verdicts from the rows the node ships.
CREATE TABLE IF NOT EXISTS spend_verdict_token (
    token_usage_id INTEGER PRIMARY KEY,
    session_id     TEXT    NOT NULL,
    shadow         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_spend_verdict_token_session ON spend_verdict_token(session_id);

CREATE TABLE IF NOT EXISTS spend_verdict_proxy (
    api_turn_id      INTEGER PRIMARY KEY,
    session_id       TEXT    NOT NULL,
    counted          INTEGER NOT NULL DEFAULT 1,
    output_tokens    INTEGER NOT NULL,
    reasoning_tokens INTEGER NOT NULL,
    inherited_fast   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_spend_verdict_proxy_session ON spend_verdict_proxy(session_id);

CREATE TABLE IF NOT EXISTS spend_verdict_dirty (
    session_id TEXT PRIMARY KEY
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS spend_verdict_state (
    k            INTEGER PRIMARY KEY CHECK (k = 1),
    rule_version INTEGER NOT NULL,
    rev          INTEGER NOT NULL
);
INSERT OR IGNORE INTO spend_verdict_state (k, rule_version, rev) VALUES (1, 0, 0);

-- api_turns: every column sessionmsg.Derive reads, plus session_id (a row
-- moved between sessions re-queues both).
CREATE TRIGGER spend_verdict_dirty_api_turns_insert
AFTER INSERT ON api_turns
WHEN COALESCE(NEW.session_id, '') <> ''
BEGIN
    INSERT INTO spend_verdict_dirty (session_id)
    SELECT NEW.session_id WHERE NOT EXISTS (SELECT 1 FROM spend_verdict_dirty WHERE session_id = NEW.session_id);
END;

CREATE TRIGGER spend_verdict_dirty_api_turns_delete
AFTER DELETE ON api_turns
WHEN COALESCE(OLD.session_id, '') <> ''
BEGIN
    INSERT INTO spend_verdict_dirty (session_id)
    SELECT OLD.session_id WHERE NOT EXISTS (SELECT 1 FROM spend_verdict_dirty WHERE session_id = OLD.session_id);
END;

CREATE TRIGGER spend_verdict_dirty_api_turns_update
AFTER UPDATE OF
    session_id, request_id, timestamp, model, input_tokens, output_tokens,
    cache_read_tokens, cache_creation_tokens, cache_creation_1h_tokens,
    web_search_requests, cost_usd, fast
ON api_turns
BEGIN
    INSERT INTO spend_verdict_dirty (session_id)
    SELECT OLD.session_id WHERE COALESCE(OLD.session_id, '') <> ''
      AND NOT EXISTS (SELECT 1 FROM spend_verdict_dirty WHERE session_id = OLD.session_id);
    INSERT INTO spend_verdict_dirty (session_id)
    SELECT NEW.session_id WHERE COALESCE(NEW.session_id, '') <> ''
      AND NOT EXISTS (SELECT 1 FROM spend_verdict_dirty WHERE session_id = NEW.session_id);
END;

-- token_usage: likewise.
CREATE TRIGGER spend_verdict_dirty_token_usage_insert
AFTER INSERT ON token_usage
WHEN COALESCE(NEW.session_id, '') <> ''
BEGIN
    INSERT INTO spend_verdict_dirty (session_id)
    SELECT NEW.session_id WHERE NOT EXISTS (SELECT 1 FROM spend_verdict_dirty WHERE session_id = NEW.session_id);
END;

CREATE TRIGGER spend_verdict_dirty_token_usage_delete
AFTER DELETE ON token_usage
WHEN COALESCE(OLD.session_id, '') <> ''
BEGIN
    INSERT INTO spend_verdict_dirty (session_id)
    SELECT OLD.session_id WHERE NOT EXISTS (SELECT 1 FROM spend_verdict_dirty WHERE session_id = OLD.session_id);
END;

CREATE TRIGGER spend_verdict_dirty_token_usage_update
AFTER UPDATE OF
    session_id, source_event_id, message_id, turn_id, timestamp, model,
    input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens,
    cache_creation_1h_tokens, reasoning_tokens, web_search_requests,
    estimated_cost_usd, fast, source_file_hash
ON token_usage
BEGIN
    INSERT INTO spend_verdict_dirty (session_id)
    SELECT OLD.session_id WHERE COALESCE(OLD.session_id, '') <> ''
      AND NOT EXISTS (SELECT 1 FROM spend_verdict_dirty WHERE session_id = OLD.session_id);
    INSERT INTO spend_verdict_dirty (session_id)
    SELECT NEW.session_id WHERE COALESCE(NEW.session_id, '') <> ''
      AND NOT EXISTS (SELECT 1 FROM spend_verdict_dirty WHERE session_id = NEW.session_id);
END;

-- sessions: the session's model is every blank-model row's default and its
-- tool selects the capability flags Derive runs with.
CREATE TRIGGER spend_verdict_dirty_sessions_insert
AFTER INSERT ON sessions
BEGIN
    INSERT INTO spend_verdict_dirty (session_id)
    SELECT NEW.id WHERE NOT EXISTS (SELECT 1 FROM spend_verdict_dirty WHERE session_id = NEW.id);
END;

CREATE TRIGGER spend_verdict_dirty_sessions_update
AFTER UPDATE OF tool, model ON sessions
BEGIN
    INSERT INTO spend_verdict_dirty (session_id)
    SELECT NEW.id WHERE NOT EXISTS (SELECT 1 FROM spend_verdict_dirty WHERE session_id = NEW.id);
END;
