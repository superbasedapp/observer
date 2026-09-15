-- 093_process_archived_windows.sql — the hot-DB marker table for the corpus
-- archival arc, Bucket B (process capture), plus the two time indexes the
-- day-window sweep rides.
-- (docs/plans/observer-corpus-archival-lazyload-design-2026-08-26.md §2.2,
-- §4.3, §9 task P3.2. Deviation D2 deferred the marker's SHAPE to this task;
-- the answer is below.)
--
-- THE UNIT IS A UTC DAY, NOT A SESSION. The design sketched
-- (session_id, until_ts) and left the choice open. Three facts settle it:
--
--   1. process_network_bodies has NO session_id at all — it hangs off
--      process_events.id — and process_events.session_id is stamped once at
--      insert and never re-attributed by the correlation sweeps (which only
--      ever UPDATE process_runs). A session-keyed archive would silently
--      strand exactly the unattributed capture that [observer.process]
--      capture_unattributed exists to collect. For the ONLY-COPY bucket,
--      stranded means lost.
--   2. The horizon this replaces (store.PruneProcessRows) is already
--      time-based, and sweeps runs on started_at and events on timestamp as
--      two INDEPENDENT clocks. The archive must move the same set the delete
--      would have removed, or the two disagree about what "cold" means — the
--      same reason Bucket A reuses the codeintel staleness query rather than
--      inventing a second definition of stale.
--   3. A day is bounded and enumerable. A session is neither: a long session
--      straddles the horizon, so "archive session X" has no well-defined
--      row set.
--
-- WHAT THE MARKER IS FOR. Not the read path — Bucket B rehydrate is
-- DIRECT-READ from the archive with no write-back (design §4.3, confirmed by
-- the operator), so a session panel answers from cold storage without
-- consulting this table for its data. The marker answers the two questions the
-- data cannot: "is this day archived or was nothing ever captured?" (the
-- honest-empty distinction, memory:feedback_honest_disable_copy) and "what did
-- cold storage take, so the aggregate storage surface can report it without
-- opening the archive file" (design §4.4 forbids a cross-database join).
--
-- It is written in the SAME transaction as the hot delete
-- (store.ProcessArchiveComplete), so no crash window exists in which the rows
-- are gone and the marker is missing.
--
-- NODE-LOCAL. Pinned in tests/invariant/privacy_test.go's forbidden-name
-- sentinel alongside the archive_* names; no paired server migration, because
-- archival state has no wire surface.

CREATE TABLE IF NOT EXISTS process_archived_windows (
    day          TEXT PRIMARY KEY,           -- UTC calendar day, 'YYYY-MM-DD'
    archived_at  INTEGER NOT NULL DEFAULT 0, -- unix seconds, move completion
    runs         INTEGER NOT NULL DEFAULT 0, -- verified cold process_runs count
    events       INTEGER NOT NULL DEFAULT 0, -- verified cold process_events count
    bodies       INTEGER NOT NULL DEFAULT 0  -- verified cold process_network_bodies count
);

CREATE INDEX IF NOT EXISTS idx_process_archived_windows_at
    ON process_archived_windows(archived_at);

-- The two time indexes the window sweep needs.
--
-- Neither exists today: process_runs is indexed (session_id, started_at),
-- (project_id, started_at), (pid, started_at) and process_events
-- (session_id, timestamp), (event_type, timestamp) — every one of them
-- LEADS with another column, so a bare `started_at < ?` / `timestamp < ?`
-- range cannot use any of them and full-scans. That is tolerable for the
-- once-per-pass PruneProcessRows it currently costs; it is NOT tolerable for
-- a per-window sweep that asks the same question repeatedly, and it is
-- exactly the O(corpus) interactive cost design §1.2 forbids.
--
-- They also make the EXISTING delete-horizon prune cheaper, so this is a
-- straight improvement independent of archival.
--
-- One-time build cost: on a corpus where process_runs is already multiple GB,
-- creating these will take a noticeable moment at the migration that adds
-- them. That is a single startup, once, in exchange for every later sweep
-- riding an index.
CREATE INDEX IF NOT EXISTS idx_process_runs_started_at
    ON process_runs(started_at);

CREATE INDEX IF NOT EXISTS idx_process_events_timestamp
    ON process_events(timestamp);
