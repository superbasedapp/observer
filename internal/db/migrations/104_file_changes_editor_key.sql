-- 104_file_changes_editor_key.sql — the session-less editor row's unique key
-- (docs/plans/lines-of-code-tracking-plan-2026-09-07.md §7 review finding L5).
--
-- WHAT WAS WRONG. Migration 103 keyed editor rows
-- UNIQUE(session_id, file_path_hash, saved_at) WHERE action_id IS NULL, and
-- session_id is NULLABLE by design: an editor save that lands outside any
-- agent session still counts toward the project-day bucket (a CLI-only
-- developer would otherwise read as 100% AI). SQLite — like the SQL standard —
-- treats two NULLs as DISTINCT for uniqueness, so that key constrains nothing
-- at all for exactly the rows that need it: re-POSTing the same save inserted
-- a second row and doubled the developer's own lines (three POSTs → 3 rows,
-- 15 lines where 5 were saved).
--
-- THE FIX. Key on COALESCE(session_id, '') instead of session_id. SQLite has
-- supported expression indexes since 3.9, and an empty string is a real value
-- to the uniqueness check, so a session-less row now collides with itself the
-- way a session-ful one always did. Every other column of the 103 key is kept,
-- in the same order, and so is the partial predicate — this migration changes
-- the NULL semantics of one key column and nothing else.
--
-- WHY THIS REPLACES A STORE-SIDE WORKAROUND. The W5 slice shipped the
-- equivalent inside internal/store/loc.go: probe for the row in the SAME
-- transaction as the write and UPDATE it when present. That was correct but it
-- is a second implementation of a uniqueness rule the schema should state
-- once, and it only protected the ONE writer that ran it. With the key fixed,
-- internal/store/loc.go::InsertFileChanges goes back to a plain ON CONFLICT
-- upsert (the same shape the action-row path uses), the probe is deleted, and
-- any future writer of file_changes gets the invariant for free.
--
-- DEDUP BEFORE THE INDEX. A node that ran the pre-fix binary can already hold
-- duplicate session-less rows, and CREATE UNIQUE INDEX over them would fail
-- the migration and leave the database unopenable. The DELETE below collapses
-- each duplicate group to its HIGHEST id first, which is last-write-wins — the
-- same answer the upsert's DO UPDATE gives, so the row that survives is the
-- row a re-POST would have produced. It touches nothing else: the predicate is
-- the index predicate (action_id IS NULL) and a group of one is left alone.
--
-- WHAT THE KEY STILL DOES NOT SAY. project_id is not part of it — it was not
-- part of 103's key either, and adding it would change what "the same save"
-- means for session-ful rows too. The residual is that two projects holding the
-- same RELATIVE path (file_path_hash is the hash of the project-relative path)
-- whose saves carry the same RFC3339-NANOSECOND timestamp would collapse into
-- one row. Documented in docs/loc-tracking.md's known limitations rather than
-- silently widened here.
--
-- NODE-LOCAL, like everything in file_changes: no column is added, no wire
-- shape moves, and there is no paired orgserver migration — what reaches an
-- org server is the per-session AGGREGATE composed by internal/store/
-- locsummary.go, never these rows (pinned by tests/invariant/privacy_test.go).

DELETE FROM file_changes
 WHERE action_id IS NULL
   AND id NOT IN (
       SELECT MAX(id) FROM file_changes
        WHERE action_id IS NULL
        GROUP BY COALESCE(session_id, ''), file_path_hash, saved_at
   );

DROP INDEX IF EXISTS idx_file_changes_editor;

-- Editor rows carry no action_id; a save is keyed by session + file + time,
-- with a session-less save keyed by the empty string rather than by a NULL
-- that is distinct from every other NULL.
CREATE UNIQUE INDEX IF NOT EXISTS idx_file_changes_editor
    ON file_changes(COALESCE(session_id, ''), file_path_hash, saved_at)
    WHERE action_id IS NULL;
