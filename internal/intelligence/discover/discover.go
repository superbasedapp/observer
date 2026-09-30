package discover

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Report is the full discover output.
type Report struct {
	Project          string             `json:"project,omitempty"`
	Days             int                `json:"days,omitempty"`
	Since            string             `json:"since,omitempty"`
	StaleReads       []StaleReadFile    `json:"stale_reads"`
	RepeatedCommands []RepeatedCommand  `json:"repeated_commands"`
	CrossToolFiles   []CrossToolFile    `json:"cross_tool_files"`
	NativeVsBash     []NativeBashBucket `json:"native_vs_bash"`
	Summary          ReportSummary      `json:"summary"`
}

// ReportSummary carries roll-up counters that the CLI prints as a header.
type ReportSummary struct {
	TotalActions   int `json:"total_actions"`
	StaleReadCount int `json:"stale_read_count"`
	// CrossThreadStaleCount is the subset of StaleReadCount where the
	// stale read crossed the parent/sub-agent boundary — the prior in-
	// session read of the same file was on the other side
	// (is_sidechain flipped). Different actionable advice from main-
	// thread stales: pass content via the Agent tool's prompt
	// parameter rather than letting the child re-read.
	CrossThreadStaleCount int   `json:"cross_thread_stale_count"`
	EstWastedTokens       int64 `json:"est_wasted_tokens"`
	RepeatedCmdGroups     int   `json:"repeated_command_groups"`
	CrossToolFileCount    int   `json:"cross_tool_file_count"`
	NativeActionCount     int   `json:"native_action_count"`
	BashActionCount       int   `json:"bash_action_count"`
}

// StaleReadFile is one file that was re-read in "stale" state multiple times.
type StaleReadFile struct {
	FilePath   string `json:"file_path"`
	Project    string `json:"project"`
	StaleCount int    `json:"stale_count"`
	// CrossThreadStaleCount is the subset of StaleCount that crossed
	// the parent/sub-agent boundary (this read on one side, the prior
	// in-session read on the other). When non-zero, the actionable
	// fix shifts from cache_control to "pass content via Agent's
	// prompt parameter".
	CrossThreadStaleCount int   `json:"cross_thread_stale_count"`
	TotalReads            int   `json:"total_reads"`
	EstWastedTokens       int64 `json:"est_wasted_tokens"`
	FileSizeBytes         int64 `json:"file_size_bytes"`
}

// RepeatedCommand is one command that ran multiple times in a project.
// NoChangeReruns is the subset of reruns where no file edits happened
// between consecutive runs — the ones truly "for free."
type RepeatedCommand struct {
	Command        string `json:"command"`
	CommandHash    string `json:"command_hash"`
	Project        string `json:"project"`
	TotalRuns      int    `json:"total_runs"`
	NoChangeReruns int    `json:"no_change_reruns"`
	Successful     int    `json:"successful_runs"`
	Failed         int    `json:"failed_runs"`
}

// CrossToolFile is one file path touched by multiple tools (spec §15.1:
// "cross-tool redundancy"). Tools list is deduped and sorted.
type CrossToolFile struct {
	FilePath string   `json:"file_path"`
	Project  string   `json:"project"`
	Tools    []string `json:"tools"`
	Accesses int      `json:"accesses"`
}

// CrossThreadStale is the cross-thread subset of a stale-rereads file
// row: same file, same session, but the prior read happened on the
// OTHER side of the parent/sub-agent boundary (the parent thread read
// it then a sub-agent re-read it, or vice versa).
type CrossThreadStale struct {
	FilePath         string `json:"file_path"`
	Project          string `json:"project"`
	CrossThreadCount int    `json:"cross_thread_count"`
	TotalReads       int    `json:"total_reads"`
	EstWastedTokens  int64  `json:"est_wasted_tokens"`
	FileSizeBytes    int64  `json:"file_size_bytes"`
}

// NativeBashBucket is action_type × is_native_tool bucket. Surfacing this
// is the easy win over RTK-style tools: we see native tool calls, not just
// Bash invocations (spec §15.1, §26 competitive table).
type NativeBashBucket struct {
	ActionType string `json:"action_type"`
	IsNative   bool   `json:"is_native"`
	Count      int    `json:"count"`
}

// Options parameterize Report.
type Options struct {
	// ProjectRoot filters to one project. Empty means all projects.
	ProjectRoot string
	// Tool filters to one tool (e.g. "claude-code"). Empty means all
	// tools. Honored by Run + WastedTokens so dashboard tiles scope
	// to the active global Tool dropdown.
	Tool string
	// Days restricts to the last N days. Zero disables.
	Days int
	// Since overrides Days when non-zero.
	Since time.Time
	// Limit caps each section's row count (stale reads, repeats, cross-tool).
	// Zero means 20.
	Limit int
	// Now overrides time.Now for deterministic tests.
	Now func() time.Time
	// StaleOnly stops Run after the stale-read pass: TotalActions, StaleReads
	// and the stale fields of Summary are exactly what a full Run returns;
	// RepeatedCommands, CrossToolFiles, NativeVsBash and their Summary fields
	// stay empty. For a reader that shows only the stale-read counts (the
	// node Overview's KPI tile), which otherwise paid for the whole report -
	// the repeated-command and no-change-rerun passes are most of its cost.
	StaleOnly bool
}

// Discoverer runs a pass against a DB.
type Discoverer struct{ db *sql.DB }

// New wraps db.
func New(db *sql.DB) *Discoverer { return &Discoverer{db: db} }

// WastedTokens returns just the estimated wasted-token total from stale
// reads over the window — skipping repeatedCommands / crossToolFiles /
// nativeVsBash. Used by the dashboard Analysis tab's headline, which only
// needs the aggregate, not the full Report. Limit defaults to 500 (matches
// what the headline used to pass to Run).
func (d *Discoverer) WastedTokens(ctx context.Context, opts Options) (int64, error) {
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	since := opts.Since
	if since.IsZero() && opts.Days > 0 {
		since = opts.Now().Add(-time.Duration(opts.Days) * 24 * time.Hour)
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = 500
	}
	stale, err := d.staleReads(ctx, opts.ProjectRoot, opts.Tool, since, limit)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, s := range stale {
		total += s.EstWastedTokens
	}
	return total, nil
}

// Run builds the report.
func (d *Discoverer) Run(ctx context.Context, opts Options) (Report, error) {
	if opts.Limit <= 0 {
		opts.Limit = 20
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	since := opts.Since
	if since.IsZero() && opts.Days > 0 {
		since = opts.Now().Add(-time.Duration(opts.Days) * 24 * time.Hour)
	}

	report := Report{
		Project: opts.ProjectRoot,
		Days:    opts.Days,
	}
	if !since.IsZero() {
		report.Since = since.UTC().Format(time.RFC3339)
	}

	total, err := d.totalActions(ctx, opts.ProjectRoot, opts.Tool, since)
	if err != nil {
		return Report{}, err
	}
	report.Summary.TotalActions = total

	stale, err := d.staleReads(ctx, opts.ProjectRoot, opts.Tool, since, opts.Limit)
	if err != nil {
		return Report{}, err
	}
	report.StaleReads = stale
	for _, s := range stale {
		report.Summary.StaleReadCount += s.StaleCount
		report.Summary.CrossThreadStaleCount += s.CrossThreadStaleCount
		report.Summary.EstWastedTokens += s.EstWastedTokens
	}
	if opts.StaleOnly {
		return report, nil
	}

	reps, err := d.repeatedCommands(ctx, opts.ProjectRoot, opts.Tool, since, opts.Limit)
	if err != nil {
		return Report{}, err
	}
	report.RepeatedCommands = reps
	report.Summary.RepeatedCmdGroups = len(reps)

	cross, err := d.crossToolFiles(ctx, opts.ProjectRoot, opts.Tool, since, opts.Limit)
	if err != nil {
		return Report{}, err
	}
	report.CrossToolFiles = cross
	report.Summary.CrossToolFileCount = len(cross)

	nb, err := d.nativeVsBash(ctx, opts.ProjectRoot, opts.Tool, since)
	if err != nil {
		return Report{}, err
	}
	report.NativeVsBash = nb
	for _, b := range nb {
		if b.IsNative {
			report.Summary.NativeActionCount += b.Count
		} else {
			report.Summary.BashActionCount += b.Count
		}
	}
	return report, nil
}

func (d *Discoverer) totalActions(ctx context.Context, projectRoot, tool string, since time.Time) (int, error) {
	q := `SELECT COUNT(*) FROM actions a
	      LEFT JOIN projects p ON p.id = a.project_id`
	var where []string
	var args []any
	if projectRoot != "" {
		where = append(where, "p.root_path = ?")
		args = append(args, projectRoot)
	}
	if tool != "" {
		where = append(where, "a.tool = ?")
		args = append(args, tool)
	}
	if !since.IsZero() {
		where = append(where, "a.timestamp >= ?")
		args = append(args, since.UTC().Format(time.RFC3339Nano))
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	var n int
	if err := d.db.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("discover: total actions: %w", err)
	}
	return n, nil
}

func (d *Discoverer) staleReads(ctx context.Context, projectRoot, tool string, since time.Time, limit int) ([]StaleReadFile, error) {
	// Join actions to file_state for sizes. The heuristic for wasted tokens
	// is stale_count * ceil(file_size / 4) — Claude's tokenizer averages
	// ~4 bytes/token for typical source code. When file_size is unknown,
	// fall back to 2KB per read (excerpt size).
	//
	// Cross-session scoping: only count a read as stale when there's an
	// earlier read of the same file in the same session. The freshness
	// engine tags reads as stale by comparing against file_state, which
	// is project-wide — so a fresh session re-reading a file changed by
	// a previous session would be tagged stale even though the new
	// session has no memory of the prior read. That's a misleading signal
	// and the EXISTS subquery filters it out.
	q := `SELECT a.target, COALESCE(p.root_path, ''),
	             SUM(CASE WHEN a.freshness = 'stale'
	                       AND EXISTS (
	                         SELECT 1 FROM actions a2
	                         WHERE a2.session_id = a.session_id
	                           AND a2.project_id = a.project_id
	                           AND a2.target     = a.target
	                           AND a2.action_type = 'read_file'
	                           AND a2.timestamp  < a.timestamp
	                       )
	                      THEN 1 ELSE 0 END) AS stale_count,
	             SUM(CASE WHEN a.freshness = 'stale'
	                       AND EXISTS (
	                         SELECT 1 FROM actions a2
	                         WHERE a2.session_id = a.session_id
	                           AND a2.project_id = a.project_id
	                           AND a2.target     = a.target
	                           AND a2.action_type = 'read_file'
	                           AND a2.timestamp  < a.timestamp
	                           AND a2.is_sidechain != a.is_sidechain
	                       )
	                      THEN 1 ELSE 0 END) AS cross_thread_count,
	             COUNT(*) AS total_reads,
	             COALESCE(MAX(fs.file_size_bytes), 0) AS size_bytes
	      FROM actions a
	      LEFT JOIN projects p ON p.id = a.project_id
	      LEFT JOIN file_state fs ON fs.project_id = a.project_id
	                              AND fs.file_path = a.target
	      WHERE a.action_type = 'read_file' AND a.target != ''`
	var args []any
	if projectRoot != "" {
		q += " AND p.root_path = ?"
		args = append(args, projectRoot)
	}
	if tool != "" {
		q += " AND a.tool = ?"
		args = append(args, tool)
	}
	if !since.IsZero() {
		q += " AND a.timestamp >= ?"
		args = append(args, since.UTC().Format(time.RFC3339Nano))
	}
	q += ` GROUP BY a.target, a.project_id
	       HAVING stale_count > 0
	       ORDER BY stale_count DESC, total_reads DESC
	       LIMIT ?`
	args = append(args, limit)

	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("discover: stale reads: %w", err)
	}
	defer rows.Close()
	var out []StaleReadFile
	for rows.Next() {
		var r StaleReadFile
		if err := rows.Scan(&r.FilePath, &r.Project, &r.StaleCount, &r.CrossThreadStaleCount, &r.TotalReads, &r.FileSizeBytes); err != nil {
			return nil, fmt.Errorf("discover: scan stale: %w", err)
		}
		tokens := r.FileSizeBytes / 4
		if tokens == 0 {
			tokens = 512 // fallback: 2KB excerpt ≈ 512 tokens.
		}
		r.EstWastedTokens = tokens * int64(r.StaleCount)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (d *Discoverer) repeatedCommands(ctx context.Context, projectRoot, tool string, since time.Time, limit int) ([]RepeatedCommand, error) {
	// Group run_command actions by (project, target). Pull success mix from
	// the actions themselves. "No-change reruns" are intervals between two
	// consecutive runs of the same command where no edit_file / write_file
	// action occurred in the same session — the cheap "did you forget you
	// already ran this" signal.
	q := `SELECT a.target, COALESCE(p.root_path, ''),
	             COUNT(*) AS total_runs,
	             SUM(CASE WHEN a.success THEN 1 ELSE 0 END) AS successful,
	             SUM(CASE WHEN NOT a.success THEN 1 ELSE 0 END) AS failed
	      FROM actions a
	      LEFT JOIN projects p ON p.id = a.project_id
	      WHERE a.action_type = 'run_command' AND a.target != ''`
	var args []any
	if projectRoot != "" {
		q += " AND p.root_path = ?"
		args = append(args, projectRoot)
	}
	if tool != "" {
		q += " AND a.tool = ?"
		args = append(args, tool)
	}
	if !since.IsZero() {
		q += " AND a.timestamp >= ?"
		args = append(args, since.UTC().Format(time.RFC3339Nano))
	}
	q += ` GROUP BY a.target, a.project_id
	       HAVING total_runs > 1
	       ORDER BY total_runs DESC
	       LIMIT ?`
	args = append(args, limit)

	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("discover: repeated commands: %w", err)
	}
	defer rows.Close()
	var out []RepeatedCommand
	for rows.Next() {
		var r RepeatedCommand
		if err := rows.Scan(&r.Command, &r.Project, &r.TotalRuns, &r.Successful, &r.Failed); err != nil {
			return nil, fmt.Errorf("discover: scan repeated: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Second pass: count no-change reruns per row in a single SQL pass.
	// The naive loop-and-query form was an N+1+M anti-pattern: for each
	// of up to 500 outer rows it issued one query to fetch the run
	// timestamps and then ANOTHER query per consecutive run pair to
	// count intervening edits — empirically ~14s of /api/discover's
	// 15s. The CTE below uses LAG() to compute prev_ts within each
	// (session, target, project) group and a single NOT EXISTS per
	// pair, replacing thousands of round-trips with one query.
	counts, err := d.noChangeRerunCounts(ctx, projectRoot, since)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].NoChangeReruns = counts[noChangeKey{project: out[i].Project, command: out[i].Command}]
	}
	return out, nil
}

type noChangeKey struct {
	project string
	command string
}

// noChangeRerunCounts returns a map[(project_root, command)] -> count of
// "no-change rerun" intervals across all run_command groups in the
// window. A no-change rerun is two consecutive runs of the same
// (session, project, command) with no edit_file / write_file in between.
// Replaces the per-group countNoChangeReruns loop with one query.
//
// The query is a single ordered pass (optimization review 2026-09-27,
// docs/audits/optimization-review-2026-09-27.md). The previous form
// answered "was there an edit between these two runs?" with a correlated
// NOT EXISTS per run pair; the only index it could seek on led with
// session_id, so every probe re-walked the WHOLE session's actions — a
// per-session quadratic that measured 30-68s of /api/discover's ~50-107s
// on a 936k-action corpus. Here the question is answered with running
// counts instead:
//
//	edits_le(t) = # edits in the session with timestamp <= t
//	edits_lt(t) = edits_le(t) - (# edits at exactly t)
//	edits strictly inside (prev, cur) = edits_lt(cur) - edits_le(prev)
//
// A difference <= 0 is exactly the old NOT EXISTS being true (it is
// negative only when prev == cur, the empty open interval the old
// predicate also treated as "no edit"). Timestamps compare as TEXT in
// both forms (BINARY collation), and the edit rows only need the window
// lower bound because prev_ts is itself >= since, so the interval can
// never reach below the window. TestNoChangeRerunCountsMatchesReference
// pins byte-identical output against the old correlated form.
func (d *Discoverer) noChangeRerunCounts(ctx context.Context, projectRoot string, since time.Time) (map[noChangeKey]int, error) {
	q := `WITH ev AS (
		SELECT a.session_id, a.target, a.project_id, a.timestamp,
		       CASE WHEN a.action_type = 'run_command' THEN 1 ELSE 0 END AS is_run,
		       CASE WHEN a.action_type IN ('edit_file', 'write_file') THEN 1 ELSE 0 END AS is_edit
		FROM actions a
		WHERE ((a.action_type = 'run_command' AND a.target != '')
		       OR a.action_type IN ('edit_file', 'write_file'))`
	var args []any
	if !since.IsZero() {
		q += " AND a.timestamp >= ?"
		args = append(args, since.UTC().Format(time.RFC3339Nano))
	}
	q += `
	),
	cum AS (
		SELECT session_id, target, project_id, timestamp, is_run,
		       SUM(is_edit) OVER (PARTITION BY session_id ORDER BY timestamp) AS edits_le,
		       SUM(is_edit) OVER (PARTITION BY session_id, timestamp) AS edits_at
		FROM ev
	),
	runs AS (
		SELECT target, project_id,
		       edits_le - edits_at AS edits_lt,
		       LAG(edits_le) OVER (PARTITION BY session_id, target, project_id ORDER BY timestamp) AS prev_edits_le
		FROM cum
		WHERE is_run = 1
	)
	SELECT r.target, COALESCE(p.root_path, '') AS project_root,
	       SUM(CASE WHEN r.edits_lt - r.prev_edits_le <= 0 THEN 1 ELSE 0 END) AS no_change_count
	FROM runs r
	LEFT JOIN projects p ON p.id = r.project_id
	WHERE r.prev_edits_le IS NOT NULL`
	if projectRoot != "" {
		q += " AND p.root_path = ?"
		args = append(args, projectRoot)
	}
	q += ` GROUP BY r.target, r.project_id`
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("discover: no-change reruns: %w", err)
	}
	defer rows.Close()
	out := map[noChangeKey]int{}
	for rows.Next() {
		var key noChangeKey
		var count int
		if err := rows.Scan(&key.command, &key.project, &count); err != nil {
			return nil, fmt.Errorf("discover: scan no-change: %w", err)
		}
		out[key] = count
	}
	return out, rows.Err()
}

func (d *Discoverer) crossToolFiles(ctx context.Context, projectRoot, tool string, since time.Time, limit int) ([]CrossToolFile, error) {
	// Cross-tool is intentionally a multi-tool signal. When the operator
	// scopes the dashboard to a single tool the question becomes
	// degenerate (a single tool can't be "cross-tool"); return early
	// with an empty slice so the panel surfaces "(no cross-tool files
	// while filtered to a single tool)" instead of producing a slow
	// EXISTS scan that times out on large action tables.
	if tool != "" {
		return []CrossToolFile{}, nil
	}
	q := `SELECT a.target, COALESCE(p.root_path, ''),
	             GROUP_CONCAT(DISTINCT a.tool) AS tools,
	             COUNT(*) AS accesses,
	             COUNT(DISTINCT a.tool) AS tool_count
	      FROM actions a
	      LEFT JOIN projects p ON p.id = a.project_id
	      WHERE a.action_type IN ('read_file', 'edit_file', 'write_file')
	            AND a.target != ''`
	var args []any
	if projectRoot != "" {
		q += " AND p.root_path = ?"
		args = append(args, projectRoot)
	}
	if !since.IsZero() {
		q += " AND a.timestamp >= ?"
		args = append(args, since.UTC().Format(time.RFC3339Nano))
	}
	q += ` GROUP BY a.target, a.project_id
	       HAVING tool_count > 1
	       ORDER BY accesses DESC
	       LIMIT ?`
	args = append(args, limit)

	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("discover: cross-tool: %w", err)
	}
	defer rows.Close()
	out := []CrossToolFile{}
	for rows.Next() {
		var r CrossToolFile
		var toolsCSV string
		var toolCount int
		if err := rows.Scan(&r.FilePath, &r.Project, &toolsCSV, &r.Accesses, &toolCount); err != nil {
			return nil, fmt.Errorf("discover: scan cross-tool: %w", err)
		}
		r.Tools = splitAndSort(toolsCSV)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (d *Discoverer) nativeVsBash(ctx context.Context, projectRoot, tool string, since time.Time) ([]NativeBashBucket, error) {
	q := `SELECT a.action_type, COALESCE(a.is_native_tool, 0), COUNT(*)
	      FROM actions a
	      LEFT JOIN projects p ON p.id = a.project_id`
	var where []string
	var args []any
	if projectRoot != "" {
		where = append(where, "p.root_path = ?")
		args = append(args, projectRoot)
	}
	if tool != "" {
		where = append(where, "a.tool = ?")
		args = append(args, tool)
	}
	if !since.IsZero() {
		where = append(where, "a.timestamp >= ?")
		args = append(args, since.UTC().Format(time.RFC3339Nano))
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	// `+a.action_type` (a no-op on the value) stops the planner from
	// walking idx_actions_type in full just to get groups pre-sorted: with
	// no ANALYZE statistics it otherwise prefers that index over the
	// window's covering timestamp index (migration 138), fetching every
	// ~4.7 KB action row of ALL time to aggregate a 30-day window (2.2 s ->
	// 0.45 s on the reference corpus). The explicit tiebreak pins the order
	// of equal counts, which previously fell out of idx_actions_type's
	// (action_type, is_native_tool) group order — the same order, now
	// stated rather than inherited from a plan.
	q += " GROUP BY +a.action_type, a.is_native_tool ORDER BY COUNT(*) DESC, a.action_type, a.is_native_tool"

	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("discover: native vs bash: %w", err)
	}
	defer rows.Close()
	var out []NativeBashBucket
	for rows.Next() {
		var b NativeBashBucket
		var native int
		if err := rows.Scan(&b.ActionType, &native, &b.Count); err != nil {
			return nil, fmt.Errorf("discover: scan native: %w", err)
		}
		b.IsNative = native != 0
		out = append(out, b)
	}
	return out, rows.Err()
}

func splitAndSort(csv string) []string {
	if csv == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	sort.Strings(parts)
	return parts
}
