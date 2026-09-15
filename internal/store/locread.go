package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/loc"
)

// Lines-of-code READ side (plan §3.2 "Reads"). Every read here goes
// through locDedupCTE, so no surface can accidentally double-count the
// codex invocation/executor pair.

// locDedupCTE is the deduplication every LOC read starts from.
//
// WHY IT EXISTS. Codex records the SAME change twice: once as the model's
// invocation (a `*** Begin Patch` envelope, or the JS wrapper carrying
// one) and once as the executor's `patch_apply_end` result (a `changes`
// map of unified diffs). Those are two different actions, so the table's
// UNIQUE(action_id, file_path_hash, source) cannot collapse them — the
// collapse key is (session_id, file_path_hash, input_digest), and
// internal/loc.normalizeBody is what makes the two renderings of one
// patch hash alike.
//
// Rows with an EMPTY digest (a path-only hook row, a truncated input, an
// editor save) are never collapsed: an empty digest is the absence of a
// fingerprint, not a shared one.
//
// The honest caveat: the same patch genuinely applied twice in one
// session — a retry after a failed apply, or an undo followed by a redo —
// also collapses to one. A retry is by far the dominant cause and
// counting it twice would be the worse error.
//
// ECHO ROWS ARE EXCLUDED HERE, once, for every read. Migration 103
// documents `editor-echo` as "kept, never counted" — the row is evidence
// that an editor reported a save, not a claim about who authored the
// lines — and the org composer already drops it. The node reads did not,
// so an echoed row surfaced inside the Unattributed bucket and the node
// card disagreed with the org panel about the same session. Filtering in
// the CTE means no future read can forget to.
//
// The one thing that must NOT come from `keep` is the human-capture flag:
// an echoed row is still proof an editor is reporting saves, so that
// detection reads file_changes directly (see LoadSessionLOC).
//
// THE TWO ARMS MUST PARTITION THE TABLE, not merely cover the common
// shapes. The collapse group is SESSION-SCOPED (it is a within-one-session
// codex pair that has to fold), so arm 1 can only speak for rows that HAVE
// a session; a session-less row therefore belongs to arm 2 whether or not
// it carries a digest, and arm 2 says so explicitly. Before that, a row
// with a NULL session_id AND a non-empty digest matched NEITHER arm and
// was invisible to every node read — unreachable today (an AI row's
// session_id is never NULL and an editor row never carries a digest), but
// the org window CTE in locsummary.go admitted exactly that row, so the
// two sides would have disagreed the moment the shape arose. Node and org
// now state the same rule.
//
// It is assembled from const fragments (locDedupCTEPrefix / -Middle /
// -Suffix) rather than rendered by a plain function call so it stays a
// compile-time constant — every reader concatenates it with other SQL
// consts (locStatsColumns) to build a query string, and gosec's G202
// check only accepts concatenation of constants, not vars. locDedupCTESQL
// below builds the parameterized (extra != "") variant from the SAME
// fragments, so the two can never drift; TestLocDedupCTEMatchesSQL pins
// that locDedupCTE == locDedupCTESQL(locDedupSessionFilter).
const locDedupCTE = locDedupCTEPrefix + locDedupSessionFilter + locDedupCTEMiddle + locDedupSessionFilter + locDedupCTESuffix

// locDedupSessionFilter is the optional per-session narrowing every
// session-scoped read binds twice ("" = every session). It sits in the
// CTE rather than the outer query so the collapse is computed over the
// session's own rows only.
const locDedupSessionFilter = `
      AND (? = '' OR session_id = ?)`

// locDedupCTEPrefix, locDedupCTEMiddle and locDedupCTESuffix are the
// three fixed fragments of the collapse-rule CTE, with the per-read
// `extra` predicate (see locDedupCTESQL) spliced in twice: once after
// the prefix (arm 1's WHERE) and once after the middle (arm 2's WHERE).
const (
	locDedupCTEPrefix = `
WITH keep AS (
    SELECT MIN(id) AS id
    FROM file_changes
    WHERE session_id IS NOT NULL AND input_digest != ''
      AND source != 'editor-echo'`
	locDedupCTEMiddle = `
    GROUP BY session_id, file_path_hash, input_digest, actor, source
    UNION ALL
    SELECT id FROM file_changes
    WHERE (input_digest = '' OR session_id IS NULL)
      AND source != 'editor-echo'`
	locDedupCTESuffix = `
)`
)

// locDedupCTESQL renders the collapse rule with an extra per-read
// predicate appended to BOTH arms (its bound parameters are therefore
// supplied twice, arm 1 first).
//
// It is a function so that every reader of file_changes — the session
// card, the window summary, the Sessions list — inherits one collapse
// rule instead of restating it. Two readers restating it is precisely how
// the list and the card came to disagree about the same session.
func locDedupCTESQL(extra string) string {
	return locDedupCTEPrefix + extra + locDedupCTEMiddle + extra + locDedupCTESuffix
}

// LOCBucket is one aggregation cell of a session's line counts: a single
// (actor, sidechain, category) combination.
type LOCBucket struct {
	Actor     string    `json:"actor"`
	Sidechain bool      `json:"sidechain"`
	Category  string    `json:"category"`
	Files     int       `json:"files"`
	Stats     loc.Stats `json:"stats"`
	// LowConfidence is how many of Files were graded below high, so the
	// UI can show the caveat next to the number rather than in a footnote.
	LowConfidence int `json:"low_confidence_files"`
	// Overwrites is how many of Files were whole-content writes over an
	// existing file, whose before-image is a reconstruction. The plan
	// forbids presenting these as measurements without a label.
	Overwrites int `json:"overwrite_files"`
	// Deleted is how many of Files the change removed entirely.
	Deleted int `json:"deleted_files"`
}

// SessionLOC is the session-scoped LOC read behind the dashboard card,
// the MCP surface and (later) the org rollup.
type SessionLOC struct {
	SessionID string `json:"session_id"`
	// Buckets is the full cross-product actually present — never a
	// pre-flattened "AI vs human" pair, because the card must be able to
	// split main from sidechain and code from docs without a second read.
	Buckets []LOCBucket `json:"buckets"`
	// Languages is the per-language file/line mix. It is a
	// content-adjacent signal (it says what KIND of file was touched),
	// which is why the org wire keeps it behind the full-content opt-in
	// even though the totals ship by default.
	Languages []LOCLanguage `json:"languages"`
	// Files is the deduplicated count of distinct files touched.
	Files int `json:"files"`
	// HumanCapture is "none" until an editor integration reports saves
	// for this session. The UI must NEVER render an "AI share" percentage
	// while it is "none" — with no human capture the denominator is
	// unknown and any share would read as 100% AI (plan §2).
	HumanCapture string `json:"human_capture"`
	// ClassifierVersion is the highest internal/loc.Version any of these
	// rows was produced by.
	ClassifierVersion int `json:"classifier_version"`
}

// LOCLanguage is one language's share of a session.
type LOCLanguage struct {
	Language string    `json:"language"`
	Category string    `json:"category"`
	Files    int       `json:"files"`
	Stats    loc.Stats `json:"stats"`
}

// locStatsColumns is the SUM projection every aggregate read shares, so
// a new bucket cannot be added to one query and forgotten in another.
const locStatsColumns = `
    SUM(fc.added_code), SUM(fc.modified_code), SUM(fc.deleted_code),
    SUM(fc.added_comment), SUM(fc.deleted_comment),
    SUM(fc.whitespace), SUM(fc.blank), SUM(fc.unknown)`

// scanLOCStats drains the locStatsColumns projection.
func scanLOCStats(rows *sql.Rows, dest ...any) (loc.Stats, error) {
	var st loc.Stats
	args := make([]any, 0, len(dest)+8)
	args = append(args, dest...)
	args = append(
		args,
		&st.AddedCode, &st.ModifiedCode, &st.DeletedCode,
		&st.AddedComment, &st.DeletedComment,
		&st.Whitespace, &st.Blank, &st.Unknown,
	)
	if err := rows.Scan(args...); err != nil {
		return st, fmt.Errorf("store.scanLOCStats: %w", err)
	}
	return st, nil
}

// LoadSessionLOC returns one session's line counts, deduplicated.
func (s *Store) LoadSessionLOC(ctx context.Context, sessionID string) (SessionLOC, error) {
	out := SessionLOC{SessionID: sessionID, HumanCapture: "none"}
	if sessionID == "" {
		return out, nil
	}
	args := []any{sessionID, sessionID, sessionID, sessionID}

	bucketQ := locDedupCTE + `
		SELECT fc.actor, fc.sidechain, fc.category, COUNT(*),
		       SUM(CASE WHEN fc.actor_confidence != 'high' THEN 1 ELSE 0 END),
		       SUM(fc.overwrite), SUM(fc.deleted_file),` + locStatsColumns + `
		FROM file_changes fc JOIN keep k ON k.id = fc.id
		GROUP BY fc.actor, fc.sidechain, fc.category
		ORDER BY fc.actor, fc.sidechain, fc.category`
	rows, err := s.db.QueryContext(ctx, bucketQ, args...)
	if err != nil {
		return out, fmt.Errorf("store.LoadSessionLOC: buckets: %w", err)
	}
	for rows.Next() {
		var b LOCBucket
		var side int
		st, serr := scanLOCStats(rows, &b.Actor, &side, &b.Category, &b.Files,
			&b.LowConfidence, &b.Overwrites, &b.Deleted)
		if serr != nil {
			_ = rows.Close()
			return out, serr
		}
		b.Sidechain = side != 0
		b.Stats = st
		out.Buckets = append(out.Buckets, b)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return out, fmt.Errorf("store.LoadSessionLOC: buckets rows: %w", err)
	}
	_ = rows.Close()

	langQ := locDedupCTE + `
		SELECT fc.language, fc.category, COUNT(*),` + locStatsColumns + `
		FROM file_changes fc JOIN keep k ON k.id = fc.id
		GROUP BY fc.language, fc.category
		ORDER BY 3 DESC`
	lrows, err := s.db.QueryContext(ctx, langQ, args...)
	if err != nil {
		return out, fmt.Errorf("store.LoadSessionLOC: languages: %w", err)
	}
	for lrows.Next() {
		var l LOCLanguage
		st, serr := scanLOCStats(lrows, &l.Language, &l.Category, &l.Files)
		if serr != nil {
			_ = lrows.Close()
			return out, serr
		}
		l.Stats = st
		out.Languages = append(out.Languages, l)
	}
	if err := lrows.Err(); err != nil {
		_ = lrows.Close()
		return out, fmt.Errorf("store.LoadSessionLOC: languages rows: %w", err)
	}
	_ = lrows.Close()

	summaryQ := locDedupCTE + `
		SELECT COUNT(DISTINCT fc.file_path_hash),
		       COALESCE(MAX(fc.classifier_version), 0)
		FROM file_changes fc JOIN keep k ON k.id = fc.id`
	if err := s.db.QueryRowContext(ctx, summaryQ, args...).
		Scan(&out.Files, &out.ClassifierVersion); err != nil {
		return out, fmt.Errorf("store.LoadSessionLOC: summary: %w", err)
	}

	// HUMAN CAPTURE IS NOT A COUNT, so it does not read through `keep`.
	// An echoed save contributes no lines, but it is still evidence that
	// an editor is reporting saves for this session — and reporting
	// "human capture: none" while an extension is plainly connected would
	// make the card claim the developer is not being measured when they
	// are.
	var editorRows sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM file_changes
		WHERE session_id = ? AND source IN ('editor','editor-echo')`,
		sessionID).Scan(&editorRows); err != nil {
		return out, fmt.Errorf("store.LoadSessionLOC: human capture: %w", err)
	}
	if editorRows.Int64 > 0 {
		out.HumanCapture = "vscode"
	}
	return out, nil
}

// SessionLOCLines is the Sessions-list row's two LOC numbers: the code
// lines (added + modified) each actor authored in one session.
//
// Deleted lines are deliberately absent. Deleting code is real work, but
// it is not lines written, and summing the two would let a delete-heavy
// refactor outscore a feature.
type SessionLOCLines struct {
	AICodeLines    int
	HumanCodeLines int
}

// locLinesChunkSize bounds the IN list per statement so a whole-corpus
// sort (the Sessions list loads the full filtered set before paging when
// the sort column is computed in Go) can never build an unbounded
// parameter list.
const locLinesChunkSize = 400

// LoadSessionLOCLines returns per-session AI and human CODE line counts
// for the given sessions, deduplicated by the SAME rule the session card
// uses.
//
// It exists because the Sessions list used to embed its own file_changes
// SQL in the dashboard package — the only raw read of this table outside
// this package — and the two copies of the collapse rule drifted: the
// card summed the MIN(id) representative of each digest group while the
// list took the group's MAX line count. For a codex invocation/executor
// pair whose executor action landed at the LOWER id (the executor's
// unified diff carries context lines, so the pair can classify
// differently) the two surfaces then reported different numbers for one
// session. One owner, one rule (CLAUDE.md #4).
//
// An unknown session simply has no entry; callers must treat a missing
// key as zero rather than as an error.
func (s *Store) LoadSessionLOCLines(ctx context.Context, sessionIDs []string) (map[string]SessionLOCLines, error) {
	out := make(map[string]SessionLOCLines, len(sessionIDs))
	if len(sessionIDs) == 0 {
		return out, nil
	}
	for start := 0; start < len(sessionIDs); start += locLinesChunkSize {
		end := start + locLinesChunkSize
		if end > len(sessionIDs) {
			end = len(sessionIDs)
		}
		chunk := sessionIDs[start:end]
		placeholders := strings.TrimRight(strings.Repeat("?,", len(chunk)), ",")
		// The IN list narrows BOTH arms of the CTE, so its values bind
		// twice; the two actor constants follow, in the outer query.
		args := make([]any, 0, 2*len(chunk)+2)
		for range 2 {
			for _, id := range chunk {
				args = append(args, id)
			}
		}
		args = append(args, LOCActorAI, LOCActorHuman)

		//nolint:gosec // G202: only the ?-placeholder list is concatenated; every value is bound.
		q := locDedupCTESQL(" AND session_id IN ("+placeholders+")") + `
			SELECT fc.session_id, fc.actor,
			       COALESCE(SUM(fc.added_code + fc.modified_code), 0)
			FROM file_changes fc JOIN keep k ON k.id = fc.id
			WHERE fc.category = 'code' AND fc.actor IN (?, ?)
			GROUP BY fc.session_id, fc.actor`
		rows, err := s.db.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, fmt.Errorf("store.LoadSessionLOCLines: %w", err)
		}
		for rows.Next() {
			var sid, actor string
			var lines int
			if err := rows.Scan(&sid, &actor, &lines); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("store.LoadSessionLOCLines: scan: %w", err)
			}
			entry := out[sid]
			switch actor {
			case LOCActorAI:
				entry.AICodeLines = lines
			case LOCActorHuman:
				entry.HumanCodeLines = lines
			}
			out[sid] = entry
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store.LoadSessionLOCLines: rows: %w", err)
		}
		_ = rows.Close()
	}
	return out, nil
}

// LOCDay is one (day, project) aggregate of line counts by actor.
type LOCDay struct {
	Day       string    `json:"day"`
	ProjectID int64     `json:"project_id"`
	Actor     string    `json:"actor"`
	Files     int       `json:"files"`
	Stats     loc.Stats `json:"stats"`
}

// LoadLOCByDay returns per-day, per-project, per-actor line counts over a
// window.
//
// It buckets on saved_at — the EVENT time — never created_at. A backfill
// of an August action must land in August; bucketing on ingest time would
// pile a year of history onto the day the operator ran the backfill.
//
// projectID 0 means every project.
func (s *Store) LoadLOCByDay(ctx context.Context, days int, projectID int64) ([]LOCDay, error) {
	if days <= 0 {
		days = 30
	}
	since := time.Now().UTC().AddDate(0, 0, -days).Format(time.RFC3339Nano)
	q := locDedupCTE + `
		SELECT substr(fc.saved_at, 1, 10) AS day, fc.project_id, fc.actor, COUNT(*),` +
		locStatsColumns + `
		FROM file_changes fc JOIN keep k ON k.id = fc.id
		WHERE fc.saved_at >= ? AND (? = 0 OR fc.project_id = ?)
		GROUP BY day, fc.project_id, fc.actor
		ORDER BY day`
	rows, err := s.db.QueryContext(ctx, q, "", "", "", "", since, projectID, projectID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadLOCByDay: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []LOCDay
	for rows.Next() {
		var d LOCDay
		st, serr := scanLOCStats(rows, &d.Day, &d.ProjectID, &d.Actor, &d.Files)
		if serr != nil {
			return nil, serr
		}
		d.Stats = st
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadLOCByDay: rows: %w", err)
	}
	return out, nil
}

// LOCSummary is the dashboard's window-scoped headline.
type LOCSummary struct {
	Days         int         `json:"days"`
	Buckets      []LOCBucket `json:"buckets"`
	ByDay        []LOCDay    `json:"by_day"`
	HumanCapture string      `json:"human_capture"`
	// CostUSD is the window's spend, so the UI can render "code lines per
	// dollar" without a second round trip. Zero when unavailable.
	CostUSD float64 `json:"cost_usd"`
}

// LoadLOCSummary returns the window-scoped headline: buckets by actor and
// category, plus the per-day series.
func (s *Store) LoadLOCSummary(ctx context.Context, days int, projectID int64) (LOCSummary, error) {
	if days <= 0 {
		days = 7
	}
	out := LOCSummary{Days: days, HumanCapture: "none"}
	since := time.Now().UTC().AddDate(0, 0, -days).Format(time.RFC3339Nano)

	q := locDedupCTE + `
		SELECT fc.actor, fc.sidechain, fc.category, COUNT(*),
		       SUM(CASE WHEN fc.actor_confidence != 'high' THEN 1 ELSE 0 END),
		       SUM(fc.overwrite), SUM(fc.deleted_file),` + locStatsColumns + `
		FROM file_changes fc JOIN keep k ON k.id = fc.id
		WHERE fc.saved_at >= ? AND (? = 0 OR fc.project_id = ?)
		GROUP BY fc.actor, fc.sidechain, fc.category
		ORDER BY fc.actor, fc.sidechain, fc.category`
	rows, err := s.db.QueryContext(ctx, q, "", "", "", "", since, projectID, projectID)
	if err != nil {
		return out, fmt.Errorf("store.LoadLOCSummary: %w", err)
	}
	for rows.Next() {
		var b LOCBucket
		var side int
		st, serr := scanLOCStats(rows, &b.Actor, &side, &b.Category, &b.Files,
			&b.LowConfidence, &b.Overwrites, &b.Deleted)
		if serr != nil {
			_ = rows.Close()
			return out, serr
		}
		b.Sidechain = side != 0
		b.Stats = st
		out.Buckets = append(out.Buckets, b)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return out, fmt.Errorf("store.LoadLOCSummary: rows: %w", err)
	}
	_ = rows.Close()

	// HUMAN CAPTURE IS "IS AN EDITOR REPORTING SAVES", not "did any row
	// come out human" — same rule as LoadSessionLOC, and it must be the
	// same rule or the window headline and the session card would answer
	// the question differently for one node.
	//
	// The two rows that would otherwise be invisible here are exactly the
	// ones the review added: an `editor-echo` (excluded from every count)
	// and a `possible_agent` save (recorded as `unknown`). Both are still
	// an editor reporting, so a node whose saves happen to be all of one
	// kind must not read as "no editor installed".
	var editorRows sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM file_changes
		WHERE source IN ('editor','editor-echo')
		  AND saved_at >= ? AND (? = 0 OR project_id = ?)`,
		since, projectID, projectID).Scan(&editorRows); err != nil {
		return out, fmt.Errorf("store.LoadLOCSummary: human capture: %w", err)
	}
	if editorRows.Int64 > 0 {
		out.HumanCapture = "vscode"
	}

	byDay, err := s.LoadLOCByDay(ctx, days, projectID)
	if err != nil {
		return out, err
	}
	out.ByDay = byDay
	return out, nil
}

// LOCEditorRow is an editor-reported save awaiting deferred
// reconciliation.
type LOCEditorRow struct {
	ID           int64
	SessionID    string
	ProjectID    int64
	FilePathHash string
	SavedAt      time.Time
}

// LoadEditorRowsPending returns editor rows in a window that have not yet
// been relabelled as echoes of an AI write.
//
// The deferred reconciliation exists because the AI row can land AFTER
// the editor save that echoes it: the extension reports a save the moment
// it happens, while the transcript the agent's edit lives in may not be
// flushed for seconds. Reconciling only forward would double-count every
// agent write the developer's editor happened to have open.
func (s *Store) LoadEditorRowsPending(ctx context.Context, since time.Time) ([]LOCEditorRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, COALESCE(session_id,''), project_id, file_path_hash, saved_at
		FROM file_changes
		WHERE source = ? AND saved_at >= ?
		ORDER BY saved_at`, LOCSourceEditor, timestamp(since))
	if err != nil {
		return nil, fmt.Errorf("store.LoadEditorRowsPending: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []LOCEditorRow
	for rows.Next() {
		var r LOCEditorRow
		var saved string
		if err := rows.Scan(&r.ID, &r.SessionID, &r.ProjectID, &r.FilePathHash, &saved); err != nil {
			return nil, fmt.Errorf("store.LoadEditorRowsPending: scan: %w", err)
		}
		r.SavedAt = parseLOCTime(saved)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadEditorRowsPending: rows: %w", err)
	}
	return out, nil
}

// MarkEditorEcho relabels an editor row as the echo of an AI write, so it
// is kept as evidence but never counted as human authorship.
func (s *Store) MarkEditorEcho(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE file_changes SET source = ?, actor = ? WHERE id = ? AND source = ?`,
		LOCSourceEditorEcho, LOCActorUnknown, id, LOCSourceEditor)
	if err != nil {
		return fmt.Errorf("store.MarkEditorEcho: %w", err)
	}
	return nil
}

// HashPath returns the hash used for file_changes.file_path_hash. It is
// exported so the editor-change endpoint hashes a human's saved path the
// SAME way an AI edit's path is hashed — if the two ever diverge, a save
// and the agent write it echoes could never join, and the deferred
// reconciliation would silently stop working.
//
// Callers must pass an ALREADY project-relative path (see
// RelativeProjectPath); this function does no normalization of its own,
// because normalizing twice is how two call sites end up disagreeing.
func HashPath(projectRelative string) string { return sha256Hex(projectRelative) }

// ProjectIDForRoot resolves a project root path to its row id, returning
// 0 when the root is not a known project.
//
// It deliberately does NOT create the project. An editor save from a
// workspace no agent has ever run in is a legitimate "nothing to attach
// to", not a reason to conjure a project row from an editor event.
func (s *Store) ProjectIDForRoot(ctx context.Context, root string) (int64, error) {
	root = strings.TrimRight(strings.TrimSpace(root), "/\\")
	if root == "" {
		return 0, nil
	}
	var id int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM projects WHERE root_path = ? OR root_path = ? LIMIT 1`,
		root, root+"/").Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("store.ProjectIDForRoot: %w", err)
	}
	return id, nil
}

// RecentSessionForProject returns the newest session in a project whose
// last action is within window of at, or "" when none is.
//
// This is the editor save's attribution rule (plan §3.3): a save lands on
// the session the developer is actually working alongside. Past the
// window it lands on nothing, and the row carries only the project-day
// bucket — which is correct, not a failure: a developer typing at 9am
// with no agent running is doing human work in a project, not in a
// session.
func (s *Store) RecentSessionForProject(
	ctx context.Context, projectID int64, at time.Time, window time.Duration,
) (string, error) {
	if projectID == 0 {
		return "", nil
	}
	var id string
	err := s.db.QueryRowContext(
		ctx, `
		SELECT session_id FROM actions
		WHERE project_id = ? AND timestamp <= ? AND timestamp >= ?
		ORDER BY timestamp DESC LIMIT 1`,
		projectID, timestamp(at), timestamp(at.Add(-window)),
	).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("store.RecentSessionForProject: %w", err)
	}
	return id, nil
}

// EditorSaveIsAIEcho reports whether an AI edit/write action touched the
// same file inside the reconciliation window around an editor save.
//
// It compares ACTION timestamps against the editor's save time, never
// ingest times: a transcript can be flushed long after the action it
// records, and reconciling on ingest time would make the answer depend on
// how busy the watcher was.
//
// The join is on the action's target hashed the same way file_changes
// hashes a path, via the file_changes rows the AI side already wrote —
// so the two halves agree by construction rather than by two independent
// path normalizations.
func (s *Store) EditorSaveIsAIEcho(
	ctx context.Context, projectID int64, filePathHash string,
	savedAt time.Time, before, after time.Duration,
) (bool, error) {
	if projectID == 0 || filePathHash == "" {
		return false, nil
	}
	var n int
	err := s.db.QueryRowContext(
		ctx, `
		SELECT COUNT(*) FROM file_changes
		WHERE project_id = ? AND file_path_hash = ?
		  AND actor = ? AND saved_at >= ? AND saved_at <= ?`,
		projectID, filePathHash, LOCActorAI,
		timestamp(savedAt.Add(-before)), timestamp(savedAt.Add(after)),
	).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("store.EditorSaveIsAIEcho: %w", err)
	}
	return n > 0, nil
}

// ReconcileEditorEchoes is the DEFERRED half of the echo rule: it
// re-examines editor rows written before the matching AI row had landed,
// and relabels the ones that turn out to be echoes.
//
// Without this, every agent write to a file the developer happened to
// have open would be counted twice — once as the agent's authorship and
// once as the developer's, because the extension reports the save
// immediately while the agent's transcript may not be flushed for
// seconds. Reconciling forward-only would systematically inflate the
// human number, which is exactly the error that would make the whole
// AI-vs-human comparison worthless.
//
// It is idempotent and safe to run repeatedly.
func (s *Store) ReconcileEditorEchoes(
	ctx context.Context, since time.Time, before, after time.Duration,
) (int, error) {
	pending, err := s.LoadEditorRowsPending(ctx, since)
	if err != nil {
		return 0, err
	}
	var n int
	for _, row := range pending {
		echo, err := s.EditorSaveIsAIEcho(ctx, row.ProjectID, row.FilePathHash, row.SavedAt, before, after)
		if err != nil {
			return n, err
		}
		if !echo {
			continue
		}
		if err := s.MarkEditorEcho(ctx, row.ID); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
