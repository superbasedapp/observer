-- 103_file_changes.sql — Lines-of-Code tracking, node-side per-file counts
-- (docs/plans/lines-of-code-tracking-plan-2026-09-07.md §3.2 / W2).
--
-- WHAT THIS IS. One row per FILE per change, carrying nothing but LINE
-- COUNTS: how many lines of code / comment / blank / whitespace-only reflow /
-- unclassifiable an AI agent's edit or a human's editor save touched. It is
-- the substrate for "how much of this session's code did the agent write, and
-- how much did the developer".
--
-- NO CONTENT. There is deliberately no column here that can hold file text, a
-- patch, a command or an excerpt. The source of every AI row is the
-- already-scrubbed, already-capped actions.raw_tool_input the store received;
-- this table records only what internal/loc counted from it. The path is
-- stored ONLY as file_path_hash = sha256(project-relative path) — never the
-- path itself — so counts join across adapters (codex reports project-relative
-- targets, claude-code absolute ones) without the path ever being readable
-- here or on any wire.
--
-- ONE OWNER. internal/store/loc.go owns every column below (CLAUDE.md
-- module-boundary rule #4). The live-ingest seam (store.Ingest) and
-- `observer backfill --loc` both go through the SAME InsertFileChanges call
-- over the SAME internal/loc.Extract, so a row captured live and the same row
-- recovered from disk are identical by construction — the mistake
-- content_bytes made (computed independently inside 16 adapters) is not
-- repeated here.
--
-- NODE-LOCAL. file_changes never enters internal/store/orgpush.go. What
-- reaches an org server is a per-session AGGREGATE composed by a separate
-- function seam (internal/store/locsummary.go, a later wave), so the privacy
-- sentinel in tests/invariant/privacy_test.go can keep forbidding the
-- `file_changes` name inside orgpush.go.
--
-- IDEMPOTENCE AND VERSIONING. classifier_version is a plain column, not part
-- of any key. Re-running the backfill after bumping internal/loc.Version
-- REPLACES a row (ON CONFLICT DO UPDATE ... WHERE excluded.classifier_version
-- > file_changes.classifier_version); re-running at the same version is a
-- no-op. Two unique keys, one per row family:
--
--   * action rows  UNIQUE(action_id, file_path_hash, source) — an action can
--     touch many files (a multi-file codex patch), and the same file can be
--     seen once per source.
--   * editor rows  UNIQUE(session_id, file_path_hash, saved_at) — an editor
--     save has no action_id; two saves of the same file a second apart are
--     two rows.
--
-- Codex emits every patch TWICE (the model's invocation row and the
-- executor's patch_apply_end row). Those are different action_ids, so the
-- unique keys cannot collapse them; the store does it on
-- (session_id, file_path_hash, input_digest) instead — hence the index below.
--
-- FORWARD KEYING FOR v2. v1 counts GROSS authorship (every line the agent
-- ever wrote, whether or not it survived). The v2 surviving-authorship ledger
-- needs to attribute a line to the change that last touched it; input_digest
-- plus the per-action/per-file grain here is enough to build that ledger
-- without rewriting this table (plan §6 ruling 4).

CREATE TABLE IF NOT EXISTS file_changes (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Attribution. session_id is nullable because an editor save that lands
    -- outside any recent session still counts toward the project-day bucket
    -- (a CLI-only developer would otherwise read as 100% AI).
    session_id        TEXT,
    project_id        INTEGER NOT NULL,
    action_id         INTEGER,

    -- Identity of the file, hashed. NEVER the path.
    file_path_hash    TEXT NOT NULL,

    -- sha256 of the normalized per-file patch text internal/loc parsed. Used
    -- ONLY to collapse the codex invocation/executor duplicate pair; it is a
    -- digest of a patch, never the patch.
    input_digest      TEXT NOT NULL DEFAULT '',

    -- internal/loc.Lang and internal/loc.Category. Language is a
    -- content-adjacent signal (it says what KIND of file), which is why the
    -- org wire puts language_mix behind the full-content opt-in even though
    -- the totals ship by default.
    language          TEXT NOT NULL DEFAULT '',
    category          TEXT NOT NULL DEFAULT 'unknown',

    -- Who made the change: 'ai' | 'human' | 'system' | 'unknown'.
    -- 'system' is a formatter-on-save delta the editor reported (will-save vs
    -- did-save), NOT a command class. 'unknown' is an unparsable or truncated
    -- input. actor_confidence is internal/loc.Confidence.
    actor             TEXT NOT NULL,
    actor_confidence  TEXT NOT NULL DEFAULT 'low',

    -- Where the row came from:
    --   'edit'         an edit_file action
    --   'write'        a write_file action
    --   'patch'        a codex patch (invocation or executor)
    --   'editor'       a VS Code save reported over the loopback POST
    --   'editor-echo'  an editor row later found to be the echo of an AI
    --                  write (deferred reconciliation) — kept, never counted
    --   'external'     a file observed changed outside the agent, lines
    --                  unknown (count of files only)
    source            TEXT NOT NULL,

    -- Splits. sidechain mirrors actions.is_sidechain: 47% of edit/write rows
    -- on the reference node are subagent work, and a session card that folds
    -- them into the main line is lying about what the developer's own agent
    -- turn produced.
    sidechain         INTEGER NOT NULL DEFAULT 0,
    -- overwrite marks a whole-content write over a file that already existed,
    -- whose before-image is a reconstructed LINE COUNT (from the preceding
    -- read) rather than text. The UI must label these; the plan forbids
    -- passing a reconstruction off as a measurement.
    overwrite         INTEGER NOT NULL DEFAULT 0,
    deleted_file      INTEGER NOT NULL DEFAULT 0,

    -- The buckets (internal/loc.Stats). All LINE counts, never bytes.
    added_code        INTEGER NOT NULL DEFAULT 0,
    modified_code     INTEGER NOT NULL DEFAULT 0,
    deleted_code      INTEGER NOT NULL DEFAULT 0,
    added_comment     INTEGER NOT NULL DEFAULT 0,
    deleted_comment   INTEGER NOT NULL DEFAULT 0,
    whitespace        INTEGER NOT NULL DEFAULT 0,
    blank             INTEGER NOT NULL DEFAULT 0,
    unknown           INTEGER NOT NULL DEFAULT 0,

    classifier_version INTEGER NOT NULL DEFAULT 0,

    -- saved_at is the editor-reported save time for 'editor'/'editor-echo'
    -- rows and the ACTION timestamp for AI rows — an event time, never an
    -- ingest time, because deferred reconciliation compares the two and a
    -- backfill would otherwise place a 2026-08 edit in today's bucket.
    saved_at          TEXT NOT NULL DEFAULT '',
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Action rows: one per (action, file, source). A multi-file codex patch
-- produces N rows under one action_id.
CREATE UNIQUE INDEX IF NOT EXISTS idx_file_changes_action
    ON file_changes(action_id, file_path_hash, source)
    WHERE action_id IS NOT NULL;

-- Editor rows carry no action_id; a save is keyed by session + file + time.
CREATE UNIQUE INDEX IF NOT EXISTS idx_file_changes_editor
    ON file_changes(session_id, file_path_hash, saved_at)
    WHERE action_id IS NULL;

-- The session card's read.
CREATE INDEX IF NOT EXISTS idx_file_changes_session
    ON file_changes(session_id);

-- The project/day trend read.
CREATE INDEX IF NOT EXISTS idx_file_changes_project_created
    ON file_changes(project_id, created_at);

-- The codex invocation/executor dedup probe.
CREATE INDEX IF NOT EXISTS idx_file_changes_digest
    ON file_changes(session_id, file_path_hash, input_digest);

-- The deferred editor-echo reconciliation probe: find editor rows whose file
-- an AI action later touched inside the reconciliation window.
CREATE INDEX IF NOT EXISTS idx_file_changes_pending_echo
    ON file_changes(file_path_hash, saved_at)
    WHERE source = 'editor';
