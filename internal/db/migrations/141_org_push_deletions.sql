-- 141_org_push_deletions.sql - org push DELETE propagation (tombstones) and the
-- session-manifest heal queue (lane R2-TOMB, 2026-09-27; builds on agent
-- migration 140 / server 178 / pg 0044 - NO new server migration: the org
-- applies a tombstone with the node_rev column 178 already added).
--
-- WHY. Migration 140 re-sends a row the node CHANGES after pushing it, but a
-- row the node DELETES after pushing it stayed on the org forever, so the org
-- over-counted what the node no longer counts: a token_usage duplicate a
-- dedup sweep removes (store.InsertTokenEvents' cursor / copilot-cli /
-- tuple / snapshot-drift sweeps, the cursor squatter eviction, a proven
-- restatement), `observer backfill` repairs (codex fork dedup, antigravity
-- markdown dedup, reasoning convergence, the openclaw session-id merge), and
-- any future dedup migration.
--
-- WHAT IS A CORRECTION AND WHAT IS NOT. Every DELETE on a tracked table is a
-- CORRECTION (class a) and propagates, EXCEPT node-local ageing / space
-- reclaim (class b: internal/retention's age + size-cap passes and their
-- orphaned-session sweep). Class b runs inside a transaction that sets the
-- schema_meta key 'org_push_retention_delete' for exactly the span of its
-- DELETEs (internal/db.WithRetentionDeletes) and every trigger below checks
-- that key. SQLite has ONE writer at a time, so a marker set and cleared
-- inside one write transaction is invisible to every other writer: a
-- correction running concurrently can never be mistaken for retention, and a
-- crash rolls the marker back with the deletes. The org keeps an aged row
-- under its OWN retention policy; the node forgetting old data is not a
-- correction. Default-propagate is the deliberate direction: an unmarked
-- future delete path over-deletes on the org only if it is really ageing,
-- which the one retention owner makes a code-review question, while the
-- opposite default silently re-opens the over-count this migration closes.
--
-- HOW. An AFTER DELETE trigger per tracked table records the deleted row's
-- WIRE IDENTITY (the key the org dedups it by) with its own change-sequence
-- value (org_push_rev, bumped once per deleted row, so seq is unique): the
-- push ships it as orgcontract.PushDeletion with NodeRev = seq, and the org
-- deletes its copy only when the copy's node_rev is OLDER than that (a row
-- the node shipped before deleting it always carries a smaller rev; a row
-- re-inserted under the same identity after the delete always carries a rev
-- >= seq and survives the tombstone in any order). Same gates as 140: the
-- node must be enrolled (floor key present) and the row above its table's
-- floor, so pre-enrolment history is never described. The row's pending
-- re-send (org_push_changes) is dropped with it.
--
-- An identity CHANGE (a future UPDATE of source_file / source_event_id, an
-- api_turns request id or timestamp, a request-less turn's session) is the
-- same fact as delete + insert: 140 re-sends the row under its new identity
-- and the triggers below tombstone the OLD identity, so the org never keeps
-- both.
--
-- A session re-inserted after a delete can reuse the deleted rowid (sessions
-- has no AUTOINCREMENT), which would put it at or below the push cursor where
-- the cursor lane never looks. org_push_insert_sessions queues such a row for
-- a re-send.
--
-- org_push_manifests is the `observer org resync --deletions` heal queue for
-- rows deleted BEFORE this migration: one row per session whose complete
-- identity digest list the push ships (orgcontract.SessionManifest) so the
-- org can drop what the node no longer has in that session; not_before is
-- the retention-safe horizon (the org never deletes an older row through a
-- manifest, so node-local ageing can never look like a deletion).
--
-- NODE-LOCAL: neither table is ever selected onto the wire; the privacy
-- sentinel pins both names out of internal/store/orgpush.go.
CREATE TABLE IF NOT EXISTS org_push_deletions (
    seq        INTEGER PRIMARY KEY,
    tbl        TEXT    NOT NULL,
    row_id     INTEGER NOT NULL,
    project_id INTEGER,
    k1         TEXT,
    k2         TEXT,
    k3         TEXT
);

CREATE TABLE IF NOT EXISTS org_push_manifests (
    session_id TEXT    PRIMARY KEY,
    seq        INTEGER NOT NULL,
    not_before TEXT    NOT NULL
) WITHOUT ROWID;

-- sessions: identity k1 = id.
CREATE TRIGGER org_push_delete_sessions
AFTER DELETE ON sessions
WHEN OLD.rowid > CAST((SELECT value FROM schema_meta WHERE key = 'org_push_floor_sessions') AS INTEGER)
 AND NOT EXISTS (SELECT 1 FROM schema_meta WHERE key = 'org_push_retention_delete')
BEGIN
    UPDATE org_push_rev SET rev = rev + 1 WHERE k = 1;
    INSERT INTO org_push_deletions (seq, tbl, row_id, project_id, k1)
    VALUES ((SELECT rev FROM org_push_rev WHERE k = 1), 'sessions', OLD.rowid, OLD.project_id, OLD.id);
    DELETE FROM org_push_changes WHERE tbl = 'sessions' AND row_id = OLD.rowid;
END;

-- actions: identity k1 = source_file, k2 = source_event_id, k3 = source_file_hash.
CREATE TRIGGER org_push_delete_actions
AFTER DELETE ON actions
WHEN OLD.id > CAST((SELECT value FROM schema_meta WHERE key = 'org_push_floor_actions') AS INTEGER)
 AND NOT EXISTS (SELECT 1 FROM schema_meta WHERE key = 'org_push_retention_delete')
BEGIN
    UPDATE org_push_rev SET rev = rev + 1 WHERE k = 1;
    INSERT INTO org_push_deletions (seq, tbl, row_id, project_id, k1, k2, k3)
    VALUES ((SELECT rev FROM org_push_rev WHERE k = 1), 'actions', OLD.id, OLD.project_id,
            OLD.source_file, OLD.source_event_id, OLD.source_file_hash);
    DELETE FROM org_push_changes WHERE tbl = 'actions' AND row_id = OLD.id;
END;

-- api_turns: identity k1 = session_id, k2 = request_id, k3 = timestamp.
CREATE TRIGGER org_push_delete_api_turns
AFTER DELETE ON api_turns
WHEN OLD.id > CAST((SELECT value FROM schema_meta WHERE key = 'org_push_floor_api_turns') AS INTEGER)
 AND NOT EXISTS (SELECT 1 FROM schema_meta WHERE key = 'org_push_retention_delete')
BEGIN
    UPDATE org_push_rev SET rev = rev + 1 WHERE k = 1;
    INSERT INTO org_push_deletions (seq, tbl, row_id, project_id, k1, k2, k3)
    VALUES ((SELECT rev FROM org_push_rev WHERE k = 1), 'api_turns', OLD.id, OLD.project_id,
            OLD.session_id, OLD.request_id, OLD.timestamp);
    DELETE FROM org_push_changes WHERE tbl = 'api_turns' AND row_id = OLD.id;
END;

-- token_usage: identity as actions; the project resolves through the session,
-- exactly as the push scopes a token row.
CREATE TRIGGER org_push_delete_token_usage
AFTER DELETE ON token_usage
WHEN OLD.id > CAST((SELECT value FROM schema_meta WHERE key = 'org_push_floor_token_usage') AS INTEGER)
 AND NOT EXISTS (SELECT 1 FROM schema_meta WHERE key = 'org_push_retention_delete')
BEGIN
    UPDATE org_push_rev SET rev = rev + 1 WHERE k = 1;
    INSERT INTO org_push_deletions (seq, tbl, row_id, project_id, k1, k2, k3)
    VALUES ((SELECT rev FROM org_push_rev WHERE k = 1), 'token_usage', OLD.id,
            (SELECT project_id FROM sessions WHERE id = OLD.session_id),
            OLD.source_file, OLD.source_event_id, OLD.source_file_hash);
    DELETE FROM org_push_changes WHERE tbl = 'token_usage' AND row_id = OLD.id;
END;

-- Identity changes: tombstone the OLD identity (140 re-sends the new one).
CREATE TRIGGER org_push_identity_sessions
AFTER UPDATE OF id ON sessions
WHEN OLD.id IS NOT NEW.id
 AND OLD.rowid > CAST((SELECT value FROM schema_meta WHERE key = 'org_push_floor_sessions') AS INTEGER)
BEGIN
    UPDATE org_push_rev SET rev = rev + 1 WHERE k = 1;
    INSERT INTO org_push_deletions (seq, tbl, row_id, project_id, k1)
    VALUES ((SELECT rev FROM org_push_rev WHERE k = 1), 'sessions', OLD.rowid, OLD.project_id, OLD.id);
END;

CREATE TRIGGER org_push_identity_actions
AFTER UPDATE OF source_file, source_event_id ON actions
WHEN (OLD.source_file IS NOT NEW.source_file OR OLD.source_event_id IS NOT NEW.source_event_id)
 AND OLD.id > CAST((SELECT value FROM schema_meta WHERE key = 'org_push_floor_actions') AS INTEGER)
BEGIN
    UPDATE org_push_rev SET rev = rev + 1 WHERE k = 1;
    INSERT INTO org_push_deletions (seq, tbl, row_id, project_id, k1, k2, k3)
    VALUES ((SELECT rev FROM org_push_rev WHERE k = 1), 'actions', OLD.id, OLD.project_id,
            OLD.source_file, OLD.source_event_id, OLD.source_file_hash);
END;

CREATE TRIGGER org_push_identity_token_usage
AFTER UPDATE OF source_file, source_event_id ON token_usage
WHEN (OLD.source_file IS NOT NEW.source_file OR OLD.source_event_id IS NOT NEW.source_event_id)
 AND OLD.id > CAST((SELECT value FROM schema_meta WHERE key = 'org_push_floor_token_usage') AS INTEGER)
BEGIN
    UPDATE org_push_rev SET rev = rev + 1 WHERE k = 1;
    INSERT INTO org_push_deletions (seq, tbl, row_id, project_id, k1, k2, k3)
    VALUES ((SELECT rev FROM org_push_rev WHERE k = 1), 'token_usage', OLD.id,
            (SELECT project_id FROM sessions WHERE id = OLD.session_id),
            OLD.source_file, OLD.source_event_id, OLD.source_file_hash);
END;

-- api_turns: a request-bearing turn is identified by (request_id, timestamp)
-- across sessions (the org relocates a moved turn on re-send), so only a
-- request id / timestamp change - or a session change of a REQUEST-LESS turn,
-- whose org key includes its session - retires the old identity.
CREATE TRIGGER org_push_identity_api_turns
AFTER UPDATE OF session_id, request_id, timestamp ON api_turns
WHEN (COALESCE(OLD.request_id, '') IS NOT COALESCE(NEW.request_id, '')
       OR OLD.timestamp IS NOT NEW.timestamp
       OR (COALESCE(OLD.request_id, '') = '' AND OLD.session_id IS NOT NEW.session_id))
 AND OLD.id > CAST((SELECT value FROM schema_meta WHERE key = 'org_push_floor_api_turns') AS INTEGER)
BEGIN
    UPDATE org_push_rev SET rev = rev + 1 WHERE k = 1;
    INSERT INTO org_push_deletions (seq, tbl, row_id, project_id, k1, k2, k3)
    VALUES ((SELECT rev FROM org_push_rev WHERE k = 1), 'api_turns', OLD.id, OLD.project_id,
            OLD.session_id, OLD.request_id, OLD.timestamp);
END;

-- A session inserted at or below the push cursor (a reused rowid after a
-- delete) is invisible to the cursor lane: queue it for a re-send.
CREATE TRIGGER org_push_insert_sessions
AFTER INSERT ON sessions
WHEN NEW.rowid <= CAST((SELECT value FROM schema_meta WHERE key = 'org_push_cursor_sessions') AS INTEGER)
 AND NEW.rowid > CAST((SELECT value FROM schema_meta WHERE key = 'org_push_floor_sessions') AS INTEGER)
BEGIN
    UPDATE org_push_rev SET rev = rev + 1 WHERE k = 1;
    INSERT OR REPLACE INTO org_push_changes (tbl, row_id, seq)
    VALUES ('sessions', NEW.rowid, (SELECT rev FROM org_push_rev WHERE k = 1));
END;
