package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// Lines-of-code tracking, node-side (docs/plans/lines-of-code-tracking-plan-2026-09-07.md §3.2).
//
// THIS FILE IS THE ONE OWNER of the file_changes table (migration 103) —
// CLAUDE.md module-boundary rule #4. Nothing else in the tree writes it.
//
// ONE PATH FOR LIVE AND BACKFILL. store.Ingest calls RecordFileChanges with
// the batch's events; `observer backfill --loc` calls BackfillLOC, which
// walks actions by keyset and hands the SAME rows to the SAME
// buildFileChanges → loc.Extract → InsertFileChanges pipeline. A row
// captured live and the same row recovered from disk are therefore
// identical by construction. This is deliberately NOT how content_bytes
// works (computed independently inside sixteen adapters), because two
// computation paths for one number is exactly how they drift.
//
// NO CONTENT LEAVES HERE. loc.Extract reads the already-scrubbed,
// already-capped actions.raw_tool_input and returns counts; this file
// hashes the path and stores nothing else.

// LOC source values. They name WHERE a row came from, not who wrote it —
// actor answers that.
const (
	LOCSourceEdit       = "edit"
	LOCSourceWrite      = "write"
	LOCSourcePatch      = "patch"
	LOCSourceEditor     = "editor"
	LOCSourceEditorEcho = "editor-echo"
	LOCSourceExternal   = "external"
)

// LOC actor values.
const (
	LOCActorAI      = "ai"
	LOCActorHuman   = "human"
	LOCActorSystem  = "system"
	LOCActorUnknown = "unknown"
)

// FileChangeRow is one file_changes row, ready to insert. It is the only
// shape this package writes; every producer (live ingest, backfill, the
// editor POST) builds one of these.
type FileChangeRow struct {
	SessionID    string
	ProjectID    int64
	ActionID     int64 // 0 = no action (an editor-reported save)
	FilePathHash string
	InputDigest  string
	Language     string
	Category     string
	Actor        string
	Confidence   string
	Source       string
	Sidechain    bool
	Overwrite    bool
	DeletedFile  bool
	Stats        loc.Stats
	Version      int
	SavedAt      time.Time
}

// insertFileChangeSQL upserts one row.
//
// The version guard is the whole point of the ON CONFLICT clause: a
// re-run of the backfill at the SAME classifier version is a no-op (so
// the command is idempotent and re-runnable at will), while a run after
// a loc.Version bump replaces every row exactly once. A row is never
// downgraded by an older binary re-walking the corpus.
//
// session_id / project_id are in the DO-UPDATE set (fleet-safety): the
// conflict key is (action_id, file_path_hash, source), so an action whose
// owning session was CORRECTED after the row was first written — e.g. the
// claude-code dedicated-file sub-agent reroute moving an action from the
// parent session to a `<parent>:agent:<id>` child on a re-parse — has its
// stored session/project brought into line on the next version-guarded
// re-count, instead of stranding a row on the pre-repair session. Latent
// on a corpus with no such stale rows, correct when one exists.
const insertFileChangeSQL = `
INSERT INTO file_changes (
    session_id, project_id, action_id, file_path_hash, input_digest,
    language, category, actor, actor_confidence, source,
    sidechain, overwrite, deleted_file,
    added_code, modified_code, deleted_code,
    added_comment, deleted_comment, whitespace, blank, unknown,
    classifier_version, saved_at
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(action_id, file_path_hash, source) WHERE action_id IS NOT NULL
DO UPDATE SET
    session_id         = excluded.session_id,
    project_id         = excluded.project_id,
    input_digest       = excluded.input_digest,
    language           = excluded.language,
    category           = excluded.category,
    actor              = excluded.actor,
    actor_confidence   = excluded.actor_confidence,
    sidechain          = excluded.sidechain,
    overwrite          = excluded.overwrite,
    deleted_file       = excluded.deleted_file,
    added_code         = excluded.added_code,
    modified_code      = excluded.modified_code,
    deleted_code       = excluded.deleted_code,
    added_comment      = excluded.added_comment,
    deleted_comment    = excluded.deleted_comment,
    whitespace         = excluded.whitespace,
    blank              = excluded.blank,
    unknown            = excluded.unknown,
    classifier_version = excluded.classifier_version,
    saved_at           = excluded.saved_at
WHERE excluded.classifier_version ` + locVersionGuardPlaceholder + ` file_changes.classifier_version`

// locVersionGuardPlaceholder is substituted for the comparison operator
// when the two upsert statements are built. SQLite cannot bind an
// operator, and building the SQL by string substitution from a CLOSED set
// of two code constants is the honest alternative to duplicating the
// whole statement twice and letting the copies drift.
const locVersionGuardPlaceholder = "{{OP}}"

// locUpsertSQL renders insertFileChangeSQL with the version guard the
// caller needs.
//
// `>` is the DEFAULT and the idempotence guarantee: a re-run at the same
// classifier version rewrites nothing.
//
// `>=` is what `--loc-rescan` needs, and the reason it exists is that the
// flag did not work. Its help text promises "use after changing a
// language table or lexer rule without bumping the version", but Rescan
// only widened the page SELECT — the upsert still rejected the row at an
// equal version, so a rescan re-read the whole corpus and wrote nothing
// (review finding M8). Passing `>=` is the smallest change that makes the
// flag do what it says: replace the row it just recomputed.
func locUpsertSQL(rescan bool) string {
	op := ">"
	if rescan {
		op = ">="
	}
	return strings.ReplaceAll(insertFileChangeSQL, locVersionGuardPlaceholder, op)
}

// insertEditorChangeSQL upserts an editor-reported row, whose unique key
// is (COALESCE(session_id, empty string), file_path_hash, saved_at)
// because it has no action.
//
// The COALESCE is migration 104 and it is load-bearing, not cosmetic: an
// editor save outside any agent session stores session_id NULL, and SQLite
// treats two NULLs as DISTINCT — so under 103's plain (session_id, …) key
// this ON CONFLICT never fired for those rows and a re-POSTed save inserted
// a duplicate, doubling the developer's own lines (review finding L5). The
// conflict target must name the index expression VERBATIM for SQLite to
// match it to the partial expression index.
const insertEditorChangeSQL = `
INSERT INTO file_changes (
    session_id, project_id, action_id, file_path_hash, input_digest,
    language, category, actor, actor_confidence, source,
    sidechain, overwrite, deleted_file,
    added_code, modified_code, deleted_code,
    added_comment, deleted_comment, whitespace, blank, unknown,
    classifier_version, saved_at
) VALUES (?,?,NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(COALESCE(session_id, ''), file_path_hash, saved_at) WHERE action_id IS NULL
DO UPDATE SET
    actor            = excluded.actor,
    actor_confidence = excluded.actor_confidence,
    source           = excluded.source,
    added_code       = excluded.added_code,
    modified_code    = excluded.modified_code,
    deleted_code     = excluded.deleted_code,
    added_comment    = excluded.added_comment,
    deleted_comment  = excluded.deleted_comment,
    whitespace       = excluded.whitespace,
    blank            = excluded.blank,
    unknown          = excluded.unknown,
    classifier_version = excluded.classifier_version`

// InsertFileChanges writes rows, skipping any whose file was recognised
// but not measurable in a way that would add nothing (a zero-count row
// for a generated file is still written, so the UI can report how many
// files were skipped and why).
//
// Rows are written in ONE transaction. A failure rolls the batch back
// rather than leaving a session half-counted.
func (s *Store) InsertFileChanges(ctx context.Context, rows []FileChangeRow) (int, error) {
	return s.insertFileChanges(ctx, rows, false)
}

// InsertFileChangesRescan is InsertFileChanges with the version guard
// relaxed to `>=`, so a row is replaced by a recomputation at the SAME
// classifier version.
//
// It exists for `observer backfill --loc --loc-rescan` and for nothing
// else. Every other writer — live ingest, the editor POST, a plain
// backfill — must keep the strict `>` guard, because that is what makes
// a re-ingest of the same transcript a no-op instead of a rewrite.
func (s *Store) InsertFileChangesRescan(ctx context.Context, rows []FileChangeRow) (int, error) {
	return s.insertFileChanges(ctx, rows, true)
}

// insertFileChanges is the shared body. rescan selects the `>=` version
// guard (see locUpsertSQL).
func (s *Store) insertFileChanges(ctx context.Context, rows []FileChangeRow, rescan bool) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.InsertFileChanges: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	actionStmt, err := tx.PrepareContext(ctx, locUpsertSQL(rescan))
	if err != nil {
		return 0, fmt.Errorf("store.InsertFileChanges: prepare action: %w", err)
	}
	defer func() { _ = actionStmt.Close() }()
	editorStmt, err := tx.PrepareContext(ctx, insertEditorChangeSQL)
	if err != nil {
		return 0, fmt.Errorf("store.InsertFileChanges: prepare editor: %w", err)
	}
	defer func() { _ = editorStmt.Close() }()

	var n int
	for _, r := range rows {
		if r.FilePathHash == "" || r.ProjectID == 0 {
			continue
		}
		var res sql.Result
		var execErr error
		switch {
		case r.ActionID != 0:
			res, execErr = actionStmt.ExecContext(
				ctx,
				nullString(r.SessionID), r.ProjectID, r.ActionID, r.FilePathHash, r.InputDigest,
				r.Language, r.Category, r.Actor, r.Confidence, r.Source,
				boolInt(r.Sidechain), boolInt(r.Overwrite), boolInt(r.DeletedFile),
				r.Stats.AddedCode, r.Stats.ModifiedCode, r.Stats.DeletedCode,
				r.Stats.AddedComment, r.Stats.DeletedComment,
				r.Stats.Whitespace, r.Stats.Blank, r.Stats.Unknown,
				r.Version, timestamp(r.SavedAt),
			)
		default:
			// EDITOR ROW, with or without a session. Both go through the
			// SAME upsert: migration 104 keys the index on
			// COALESCE(session_id,''), so a session-less save collides with
			// itself and the ON CONFLICT fires. Before 104 it did not (two
			// NULLs are DISTINCT to SQLite), and this arm carried a
			// probe-then-update workaround for the session-less case —
			// deleted with the migration, because a uniqueness rule the
			// schema states is one the schema should enforce for every
			// writer, not one each writer re-implements.
			res, execErr = editorStmt.ExecContext(
				ctx,
				nullString(r.SessionID), r.ProjectID, r.FilePathHash, r.InputDigest,
				r.Language, r.Category, r.Actor, r.Confidence, r.Source,
				boolInt(r.Sidechain), boolInt(r.Overwrite), boolInt(r.DeletedFile),
				r.Stats.AddedCode, r.Stats.ModifiedCode, r.Stats.DeletedCode,
				r.Stats.AddedComment, r.Stats.DeletedComment,
				r.Stats.Whitespace, r.Stats.Blank, r.Stats.Unknown,
				r.Version, timestamp(r.SavedAt),
			)
		}
		if execErr != nil {
			return n, fmt.Errorf("store.InsertFileChanges: exec: %w", execErr)
		}
		if affected, err := res.RowsAffected(); err == nil && affected > 0 {
			n++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.InsertFileChanges: commit: %w", err)
	}
	return n, nil
}

// locActionRow is one edit/write action as the LOC pipeline reads it.
type locActionRow struct {
	ID            int64
	SessionID     string
	ProjectID     int64
	ProjectRoot   string
	ActionType    string
	Target        string
	RawToolInput  string
	Sidechain     bool
	PriorActionID int64
	Timestamp     string
}

// locActionSelect is the projection every LOC read uses. It deliberately
// selects raw_tool_input and NOTHING else content-bearing: no output, no
// reasoning, no error message.
//
// A sub-agent's own edit keeps its HONEST stored is_sidechain: a sub-agent
// session is a first-class session whose own card must read its work as
// main-line, not sidechain. The sub-agent/parent split is derived at
// PARENT read time only (internal/store/locread.go::LoadSessionLOC), never
// stamped here — so a claude-code dedicated-file child, an opencode
// sub-agent session, etc. each stays truthful about its own lines.
const locActionSelect = `
SELECT a.id, a.session_id, a.project_id, p.root_path, a.action_type,
       a.target, a.raw_tool_input, a.is_sidechain,
       COALESCE(a.prior_action_id, 0), a.timestamp
FROM actions a
JOIN projects p ON p.id = a.project_id`

// scanLOCActions drains a locActionSelect result set.
func scanLOCActions(rows *sql.Rows) ([]locActionRow, error) {
	defer func() { _ = rows.Close() }()
	var out []locActionRow
	for rows.Next() {
		var r locActionRow
		var sess, target, raw sql.NullString
		var side int
		if err := rows.Scan(&r.ID, &sess, &r.ProjectID, &r.ProjectRoot, &r.ActionType,
			&target, &raw, &side, &r.PriorActionID, &r.Timestamp); err != nil {
			return nil, fmt.Errorf("store.scanLOCActions: scan: %w", err)
		}
		r.SessionID = sess.String
		r.Target = target.String
		r.RawToolInput = raw.String
		r.Sidechain = side != 0
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.scanLOCActions: rows: %w", err)
	}
	return out, nil
}

// RecordFileChanges is the SINGLE live-ingest seam for lines-of-code
// tracking. store.Ingest calls it once per batch, after every action row
// exists.
//
// It resolves each edit/write event back to its stored action row by the
// same (source_file, source_event_id) key the action upsert uses, rather
// than threading action ids through Ingest — which keeps store.go's
// footprint to one call and means a row re-ingested from a re-parsed
// transcript re-counts against the SAME action, never a duplicate.
//
// Failure-isolated by its caller: a LOC problem must never fail an
// ingest, so Ingest reports the error and moves on.
func (s *Store) RecordFileChanges(ctx context.Context, events []models.ToolEvent) (int, error) {
	// Group the batch's edit/write events by source_file, so the lookup
	// is one indexed query per file rather than one per event.
	byFile := map[string][]string{}
	for _, e := range events {
		if !isLOCActionType(e.ActionType) || strings.TrimSpace(e.RawToolInput) == "" {
			continue
		}
		if e.SourceFile == "" || e.SourceEventID == "" {
			continue
		}
		byFile[e.SourceFile] = append(byFile[e.SourceFile], e.SourceEventID)
	}
	if len(byFile) == 0 {
		return 0, nil
	}

	var actionRows []locActionRow
	for file, ids := range byFile {
		for _, chunk := range chunkStrings(ids, locLookupChunk) {
			//nolint:gosec // G202: placeholders(len(chunk)) is a generated `?` placeholder run; ids bind via args.
			q := locActionSelect + ` WHERE a.source_file = ? AND a.source_event_id IN (` +
				placeholders(len(chunk)) + `)`
			args := make([]any, 0, len(chunk)+1)
			args = append(args, file)
			for _, id := range chunk {
				args = append(args, id)
			}
			rows, err := s.db.QueryContext(ctx, q, args...)
			if err != nil {
				return 0, fmt.Errorf("store.RecordFileChanges: query: %w", err)
			}
			got, err := scanLOCActions(rows)
			if err != nil {
				return 0, err
			}
			actionRows = append(actionRows, got...)
		}
	}
	return s.processLOCActions(ctx, actionRows)
}

// locLookupChunk bounds how many source_event_ids go into one IN clause.
// SQLite's default variable limit is 999; 400 leaves generous headroom.
const locLookupChunk = 400

// processLOCActions runs the extract-and-insert pipeline over already-read
// action rows. Live ingest and backfill both land here, which is what
// makes the two paths identical by construction.
func (s *Store) processLOCActions(ctx context.Context, actions []locActionRow) (int, error) {
	if len(actions) == 0 {
		return 0, nil
	}
	rows := make([]FileChangeRow, 0, len(actions))
	for _, a := range actions {
		built, err := s.buildFileChanges(ctx, a)
		if err != nil {
			return 0, err
		}
		rows = append(rows, built...)
	}
	n, err := s.InsertFileChanges(ctx, rows)
	if err != nil {
		return 0, err
	}

	// Deferred editor-echo reconciliation (plan §3.3), triggered by the
	// arrival of the AI rows rather than by a timer: an editor save the
	// extension reported BEFORE this transcript was flushed can only be
	// recognised as an echo now. Scoped to the window around the earliest
	// row in this batch, so a backfill of a year of history does not walk
	// a year of editor rows. An editor save at S can echo an AI row at A
	// only when A ∈ [S-LOCEchoBefore, S+LOCEchoAfter], i.e. only when
	// S >= A-LOCEchoAfter — hence the offset below.
	//
	// Failure-isolated: an echo that is missed leaves a human row that
	// double-counts an agent write, which is bad but recoverable; a
	// reconciliation error that failed the ingest would be worse.
	if earliest, ok := earliestSavedAt(rows); ok {
		if _, rerr := s.ReconcileEditorEchoes(
			ctx, earliest.Add(-LOCEchoAfter), LOCEchoBefore, LOCEchoAfter,
		); rerr != nil {
			warnLOC("editor-echo reconcile", rerr)
		}
	}
	return n, nil
}

// earliestSavedAt returns the oldest SavedAt across rows.
func earliestSavedAt(rows []FileChangeRow) (time.Time, bool) {
	var out time.Time
	for _, r := range rows {
		if r.SavedAt.IsZero() {
			continue
		}
		if out.IsZero() || r.SavedAt.Before(out) {
			out = r.SavedAt
		}
	}
	return out, !out.IsZero()
}

// buildFileChanges turns one action row into its per-file LOC rows.
func (s *Store) buildFileChanges(ctx context.Context, a locActionRow) ([]FileChangeRow, error) {
	in := loc.Input{
		RawToolInput: a.RawToolInput,
		ActionType:   a.ActionType,
		Target:       a.Target,
		BeforeLines:  -1,
	}
	// The before-image reconstruction is only meaningful for a
	// whole-content write, and it costs an indexed lookup, so it is
	// gated on the action type rather than run for all 51k rows.
	if a.ActionType == models.ActionWriteFile {
		before, existed, err := s.beforeImageLines(ctx, a)
		if err != nil {
			return nil, err
		}
		// EXISTED and MEASURED are two different facts, and conflating
		// them is what made a truncated read look like a brand-new file.
		// A prior read proves the file existed; only an UNtruncated one
		// yields a before-image line count (review finding L4).
		in.Existed = existed || a.PriorActionID != 0
		in.BeforeLines = before
	}

	stats := loc.Extract(in)
	if len(stats) == 0 {
		return nil, nil
	}
	source := locSourceFor(a, stats)
	saved := parseLOCTime(a.Timestamp)

	out := make([]FileChangeRow, 0, len(stats))
	for _, fs := range stats {
		out = append(out, FileChangeRow{
			SessionID:    a.SessionID,
			ProjectID:    a.ProjectID,
			ActionID:     a.ID,
			FilePathHash: sha256Hex(RelativeProjectPath(a.ProjectRoot, fs.Path)),
			InputDigest:  fs.InputDigest,
			Language:     string(fs.Lang),
			Category:     string(fs.Category),
			Actor:        locActorFor(fs),
			Confidence:   string(fs.Confidence),
			Source:       source,
			Sidechain:    a.Sidechain,
			Overwrite:    fs.Overwrite,
			DeletedFile:  fs.DeletedFile,
			Stats:        fs.Stats,
			Version:      loc.Version,
			SavedAt:      saved,
		})
	}
	return out, nil
}

// locSourceTable maps an action's shape onto its file_changes source.
// A codex patch is its own source because the SAME change arrives twice
// — once as the model's invocation and once as the executor's result —
// and collapsing that pair needs both rows to agree on the source value.
var locSourceTable = map[loc.Shape]string{
	loc.ShapeCodexChanges: LOCSourcePatch,
	loc.ShapeCodexPatch:   LOCSourcePatch,
	loc.ShapeCodexJS:      LOCSourcePatch,
}

// locSourceFor picks the source for an action's rows from the shape the
// ladder matched, falling back to the action type.
func locSourceFor(a locActionRow, stats []loc.FileStats) string {
	if len(stats) > 0 {
		if src, ok := locSourceTable[stats[0].Shape]; ok {
			return src
		}
	}
	if a.ActionType == models.ActionWriteFile {
		return LOCSourceWrite
	}
	return LOCSourceEdit
}

// locActorFor decides who authored a file's lines. Every row this file
// builds comes from an AI tool call, so the only question is whether the
// input was measurable: a shape the ladder could not read is honestly
// `unknown`, not a zero-line AI contribution.
func locActorFor(fs loc.FileStats) string {
	switch fs.Shape {
	case loc.ShapeTruncated, loc.ShapePathOnly, loc.ShapeUnrecognized:
		return LOCActorUnknown
	default:
		return LOCActorAI
	}
}

// beforeImageLines recovers the line count of a file as it stood before a
// whole-content write, from the most recent READ of the same file in the
// same session.
//
// This is a RECONSTRUCTION, not a measurement, and the row it feeds is
// stamped overwrite=true and medium confidence so the UI says so (plan
// §6 ruling 3, acceptance criterion 3). The query rides
// idx_actions_session_target_action_ts.
//
// It returns TWO independent facts, because they are independent:
//
//	lines   the before-image LINE COUNT, or -1 when it is not knowable
//	existed whether a prior read proves the file was already there
//
// A truncated or windowed read gives (−1, true): the file existed, and
// its size is unknown. Folding those into one "found" answer is what made
// a 6,000-line file read at the default 2,000-line limit and then
// rewritten report 2,000 un-measured lines (review finding L4).
func (s *Store) beforeImageLines(ctx context.Context, a locActionRow) (int, bool, error) {
	if a.SessionID == "" || a.Target == "" {
		return -1, false, nil
	}
	var out sql.NullString
	err := s.db.QueryRowContext(
		ctx, `
		SELECT raw_tool_output FROM actions
		WHERE session_id = ? AND target = ? AND action_type = ?
		  AND timestamp < ? AND raw_tool_output IS NOT NULL AND raw_tool_output != ''
		ORDER BY timestamp DESC LIMIT 1`,
		a.SessionID, a.Target, models.ActionReadFile, a.Timestamp,
	).Scan(&out)
	if errors.Is(err, sql.ErrNoRows) {
		return -1, false, nil
	}
	if err != nil {
		return -1, false, fmt.Errorf("store.beforeImageLines: %w", err)
	}
	if out.String == "" {
		return -1, false, nil
	}
	if readOutputIsPartial(out.String) {
		// A PARTIAL read is not a smaller file, it is an unknown one.
		// Counting its lines would book the difference between the window
		// and the real file as lines the agent "added". The file did
		// exist — the read proves that — so the row is still an
		// overwrite; it just has no before-image, which downgrades it to
		// low confidence, and the UI already labels that.
		return -1, true, nil
	}
	return len(loc.SplitLines(out.String)), true, nil
}

// readWindowLimit is claude-code's default Read page size. A read whose
// output is exactly this many numbered lines is at the limit, so the file
// is at least that long and may be longer — the count is a floor, not a
// measurement.
const readWindowLimit = 2000

// readOutputIsPartial reports whether a stored raw_tool_output from a
// file read is a WINDOW onto the file rather than the whole of it.
//
// Three ways a read comes back partial, all of them observable in the
// stored text and none of them recorded as a flag:
//
//  1. internal/scrub capped the output at MaxRawOutputBytes and appended
//     its "…[truncated]" marker.
//  2. The tool paginated: claude-code numbers each line `%6d\t`, so an
//     output whose FIRST numbered line is not line 1 was read with an
//     `offset`, and one that is exactly readWindowLimit lines long hit
//     the default `limit`.
//  3. The tool said so in words — several adapters append a
//     "(Results are truncated…)" / "[truncated]" note of their own.
//
// It is deliberately conservative in the direction of "unknown": a false
// positive costs a medium-confidence row its before-image and downgrades
// it to low, while a false negative silently invents added lines.
func readOutputIsPartial(text string) bool {
	if strings.Contains(text, "…[truncated]") ||
		strings.Contains(text, "[truncated]") ||
		strings.Contains(text, "Results are truncated") {
		return true
	}
	lines := loc.SplitLines(text)
	first, ok := leadingLineNumber(lines)
	if !ok {
		// Not a line-numbered read; nothing more can be told from the
		// shape, so trust it.
		return false
	}
	if first > 1 {
		return true // read with an offset
	}
	return len(lines) >= readWindowLimit
}

// leadingLineNumber pulls the line number off the first line of a
// line-numbered read output (`     1\tpackage main`), reporting whether
// the output is numbered at all.
func leadingLineNumber(lines []string) (int, bool) {
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		tab := strings.IndexByte(line, '\t')
		if tab <= 0 {
			return 0, false
		}
		digits := strings.TrimSpace(line[:tab])
		if digits == "" {
			return 0, false
		}
		n := 0
		for i := 0; i < len(digits); i++ {
			if digits[i] < '0' || digits[i] > '9' {
				return 0, false
			}
			n = n*10 + int(digits[i]-'0')
		}
		return n, true
	}
	return 0, false
}

// The deferred editor-echo reconciliation window (plan §3.3). An editor
// save is the ECHO of an AI write when an AI row for the same file
// carries an ACTION timestamp inside [saved_at-Before, saved_at+After].
//
// ONE OWNER: both the live POST handler (which checks forward, at save
// time) and the deferred pass (which checks backward, when the AI row
// finally lands) read these, so the two directions cannot disagree about
// what counts as the same event.
//
// DIRECTION. The window is asymmetric, and it leans BACKWARD because the
// causal order is agent-writes → editor-reloads → developer-saves: the AI
// action PRECEDES the save it is echoed by. It shipped leaning the other
// way (5s back, 60s forward), which turned the everyday collaboration —
// the developer hand-edits a file, saves, and then asks the agent to
// carry on in it — into an "echo", relabelling genuine human work as the
// agent's and driving the human number to zero in exactly the sessions
// the feature exists to measure (review finding M1).
//
// The forward half is now clock skew only, not a causal window. It is
// non-zero because the editor stamps saved_at from ITS clock while the AI
// row carries the transcript's, and the two can disagree by a second or
// two on the same machine. What it must never do is reach far enough
// forward to swallow an agent edit the developer's save CAUSED rather
// than echoed.
//
// Deferral is unaffected: a transcript can still be flushed long after
// the action it records, which is why the backward pass exists at all —
// but the AI ACTION timestamp it compares is still before the save.
const (
	LOCEchoBefore = 60 * time.Second
	LOCEchoAfter  = 5 * time.Second
)

// isLOCActionType reports whether an action type carries authored file
// content worth counting.
func isLOCActionType(t string) bool {
	return t == models.ActionEditFile || t == models.ActionWriteFile
}

// RelativeProjectPath normalizes a tool-reported path into the
// project-relative form whose sha256 is file_path_hash.
//
// It is exported because the editor POST handler must hash a path
// IDENTICALLY to the way an AI edit's path is hashed — otherwise a human
// save and the agent edit it echoes would never join, and the deferred
// editor-echo reconciliation could not work.
//
// Normalization, in order:
//
//  1. Both separators become "/", so a Windows session's
//     `C:\repo\src\a.go` and a WSL session's `/repo/src/a.go` reduce the
//     same way. (The corpus really does mix them: 3 sessions here span
//     Windows and Linux roots.)
//  2. The project root prefix is stripped when present, case-insensitively
//     — Windows paths are case-insensitive in practice and a drive-letter
//     case difference must not fork the hash.
//  3. A leading "./" and any leading "/" are stripped.
//
// A path that is NOT under the root (an absolute path in another tree, an
// "[external]/…" pseudo-path) is returned normalized but unstripped, so it
// hashes distinctly and never collides with a project file.
func RelativeProjectPath(projectRoot, path string) string {
	p := strings.ReplaceAll(strings.TrimSpace(path), `\`, "/")
	if p == "" {
		return ""
	}
	root := strings.TrimSuffix(strings.ReplaceAll(strings.TrimSpace(projectRoot), `\`, "/"), "/")
	if root != "" && len(p) > len(root) &&
		strings.EqualFold(p[:len(root)], root) &&
		(p[len(root)] == '/') {
		p = p[len(root)+1:]
	}
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimLeft(p, "/")
	return p
}

// parseLOCTime decodes an actions.timestamp value, falling back to the
// zero time (which timestamp() renders as "now") when the stored value is
// unparseable. It never uses ingest time for a real event: a backfill of
// an August action must bucket in August.
func parseLOCTime(s string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// chunkStrings splits ids into batches of at most n.
func chunkStrings(ids []string, n int) [][]string {
	if n <= 0 || len(ids) <= n {
		return [][]string{ids}
	}
	var out [][]string
	for len(ids) > n {
		out = append(out, ids[:n])
		ids = ids[n:]
	}
	if len(ids) > 0 {
		out = append(out, ids)
	}
	return out
}

// placeholders renders n comma-separated SQL placeholders.
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// nullString renders "" as SQL NULL, so a session-less editor row stores
// NULL rather than an empty string that the unique index would treat as a
// real value.
func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// BackfillLOCOptions bounds one `observer backfill --loc` run.
type BackfillLOCOptions struct {
	// Since, when non-zero, skips actions older than this timestamp.
	Since time.Time
	// Limit, when > 0, stops after this many ACTIONS (not rows).
	Limit int
	// Rescan re-reads actions that already have rows at the current
	// classifier version. The default skips them, which is what makes a
	// re-run cheap.
	Rescan bool
	// DryRun computes everything and writes nothing.
	DryRun bool
	// Progress, when non-nil, is called after each page with the
	// running action and row counts.
	Progress func(actions, rows int)
}

// BackfillLOCResult reports what a backfill run did.
type BackfillLOCResult struct {
	ActionsScanned int
	RowsWritten    int
	FilesSeen      int
	// PerSession is the per-session row total, populated for dry runs so
	// an operator can eyeball a specific session without writing.
	PerSession map[string]loc.Stats
}

// locBackfillPage is how many actions one read transaction pulls. The
// live database is tens of gigabytes, so the backfill must never hold a
// long read transaction open: it pages by keyset on actions.id, which is
// the primary key, so each page is a range scan with no offset cost.
const locBackfillPage = 500

// BackfillLOC walks every edit/write action and (re)computes its LOC
// rows.
//
// Idempotent: at the same loc.Version a re-run rewrites nothing (the
// upsert's version guard rejects it) and, unless Rescan is set, does not
// even read rows that already have current-version counts.
func (s *Store) BackfillLOC(ctx context.Context, opts BackfillLOCOptions) (BackfillLOCResult, error) {
	res := BackfillLOCResult{PerSession: map[string]loc.Stats{}}
	var cursor int64
	for {
		if opts.Limit > 0 && res.ActionsScanned >= opts.Limit {
			break
		}
		page := locBackfillPage
		if opts.Limit > 0 && opts.Limit-res.ActionsScanned < page {
			page = opts.Limit - res.ActionsScanned
		}
		batch, err := s.loadLOCBackfillPage(ctx, cursor, page, opts)
		if err != nil {
			return res, err
		}
		if len(batch) == 0 {
			break
		}
		cursor = batch[len(batch)-1].ID
		res.ActionsScanned += len(batch)

		var rows []FileChangeRow
		for _, a := range batch {
			built, err := s.buildFileChanges(ctx, a)
			if err != nil {
				return res, err
			}
			rows = append(rows, built...)
			for _, r := range built {
				agg := res.PerSession[r.SessionID]
				agg.Add(r.Stats)
				res.PerSession[r.SessionID] = agg
			}
		}
		res.FilesSeen += len(rows)
		if !opts.DryRun {
			// Rescan means "recount at the current version", so it must
			// also be allowed to REPLACE the row it just recomputed —
			// otherwise the pass reads every action and writes nothing
			// (review finding M8).
			write := s.InsertFileChanges
			if opts.Rescan {
				write = s.InsertFileChangesRescan
			}
			n, err := write(ctx, rows)
			if err != nil {
				return res, err
			}
			res.RowsWritten += n
		}
		if opts.Progress != nil {
			opts.Progress(res.ActionsScanned, res.FilesSeen)
		}
	}
	return res, nil
}

// loadLOCBackfillPage reads one keyset page of candidate actions.
func (s *Store) loadLOCBackfillPage(
	ctx context.Context, after int64, limit int, opts BackfillLOCOptions,
) ([]locActionRow, error) {
	var where strings.Builder
	args := []any{models.ActionEditFile, models.ActionWriteFile, after}
	where.WriteString(` WHERE a.action_type IN (?,?) AND a.id > ?
		AND a.raw_tool_input IS NOT NULL AND a.raw_tool_input != ''`)
	if !opts.Since.IsZero() {
		where.WriteString(` AND a.timestamp >= ?`)
		args = append(args, timestamp(opts.Since))
	}
	if !opts.Rescan {
		// Skip actions already counted at the current version. NOT EXISTS
		// on the unique index is a single probe per candidate row.
		where.WriteString(` AND NOT EXISTS (
			SELECT 1 FROM file_changes fc
			WHERE fc.action_id = a.id AND fc.classifier_version >= ?)`)
		args = append(args, loc.Version)
	}
	where.WriteString(` ORDER BY a.id LIMIT ?`)
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, locActionSelect+where.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("store.loadLOCBackfillPage: %w", err)
	}
	return scanLOCActions(rows)
}

// warnLOC reports a non-fatal LOC problem without failing the caller.
func warnLOC(stage string, err error) {
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "store: loc %s non-fatal err: %v\n", stage, err)
}
