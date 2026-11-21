-- 222_tool_installs_subject.sql: sandbox prerequisites share the guided-install
-- record (subject_kind = 'sandbox'; tool holds the prerequisite id). Sandbox
-- installation lifecycle plan section 9, ruling R3 (one install record, one
-- writer), task PT-89.
--
-- subject_kind says whose record a row is: 'tool' (an AI tool installed from
-- the New Terminal dialog, migration 149's rows, the default every existing
-- row reads) or 'sandbox' (one step of a sandbox backend's setup, where tool
-- holds the prerequisite id of internal/sandboxsetup's table). backend is
-- the sandbox backend the step was set up for. source, digest and
-- placed_path describe a pinned download (vendor_release, org_mirror or
-- from_file; the sha256 of the placed file; the path Observer placed it at),
-- so an undo removes only the file Observer placed after re-checking its
-- digest. elevated records that the step ran under sudo or UAC. Every
-- read and every compare-and-set in internal/store/toolinstalls.go, the ONE
-- writer of this table, filters by subject_kind, including the
-- latest-record guard.
--
-- NODE-LOCAL: install records describe this machine's own software. NEVER
-- selected by internal/store/orgpush.go; tool_installs is already in the
-- forbidden-table sentinel (tests/invariant/privacy_test.go). No paired
-- server migration.
--
-- 222 sits below steps this line already shipped (230 to 248), so it is a
-- node late step: SQLite has no ADD COLUMN IF NOT EXISTS, and a pre-ledger
-- database recorded at 230 or above would otherwise skip it. lateSteps in
-- internal/db/db.go probes tool_installs.subject_kind: a database that has
-- the column adopts the step, any other runs it (docs/migration-numbering.md).

ALTER TABLE tool_installs ADD COLUMN subject_kind TEXT NOT NULL DEFAULT 'tool';
ALTER TABLE tool_installs ADD COLUMN backend      TEXT NOT NULL DEFAULT '';
ALTER TABLE tool_installs ADD COLUMN source       TEXT NOT NULL DEFAULT '';
ALTER TABLE tool_installs ADD COLUMN digest       TEXT NOT NULL DEFAULT '';
ALTER TABLE tool_installs ADD COLUMN placed_path  TEXT NOT NULL DEFAULT '';
ALTER TABLE tool_installs ADD COLUMN elevated     INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_tool_installs_subject ON tool_installs(subject_kind, tool, id);
