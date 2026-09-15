-- 092_codeintel_archived_projects.sql — the hot-DB marker table for the
-- corpus archival arc, Bucket A
-- (docs/plans/observer-corpus-archival-lazyload-design-2026-08-26.md §5.1, §9
-- task P1.3).
--
-- WHY A MARKER AT ALL. Once a project's codeintel_* rows have moved to
-- ~/.observer/archive.db, "no rows for this project" becomes ambiguous: it
-- means EITHER "archived, one rehydrate away" OR "never indexed". Those two
-- states need completely different answers from `observer index --status` and
-- from the MCP symbol tools, and telling them apart must not cost opening the
-- archive file on the common path. One indexed row per archived project
-- answers it with a primary-key lookup — O(1) per archived unit, never
-- O(corpus).
--
-- It is written in the SAME transaction as the hot delete
-- (store.CodeIntelArchiveComplete), so there is no crash window in which the
-- rows are gone but the marker is missing — which is precisely the state that
-- would make an archived project look permanently un-indexed.
--
-- last_indexed_at is the MAX(codeintel_files.indexed_at) watermark the project
-- carried at archival: the date a surface reports as "archived, last indexed
-- <date>", and the value the delete re-checks to abort on a concurrent
-- re-index.
--
-- rows_archived lets the aggregate storage surface (design §4.4) report
-- "N projects archived, M rows" from the hot DB alone, without joining across
-- the two databases — a join this design explicitly forbids.
--
-- NODE-LOCAL. Same posture as the codeintel_* tables it shadows: it names
-- private project paths and must never leave the machine. Pinned in
-- tests/invariant/privacy_test.go's forbidden-name sentinel alongside the
-- archive_* table names, and excluded from internal/store/orgpush.go by
-- construction (that seam selects an explicit allow-list this is not in).
-- No paired server migration: there is no wire surface for archival state.

CREATE TABLE IF NOT EXISTS codeintel_archived_projects (
    project         TEXT PRIMARY KEY,          -- git-root identity, as in codeintel_files
    archived_at     INTEGER NOT NULL DEFAULT 0, -- unix seconds, move completion
    last_indexed_at INTEGER NOT NULL DEFAULT 0, -- MAX(codeintel_files.indexed_at) at archival
    rows_archived   INTEGER NOT NULL DEFAULT 0  -- verified cold row count
);

CREATE INDEX IF NOT EXISTS idx_codeintel_archived_projects_at
    ON codeintel_archived_projects(archived_at);
