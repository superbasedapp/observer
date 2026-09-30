package diag

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cursorusage"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// cursorUsageWindow bounds the sessions checkCursorUsage looks at.
const cursorUsageWindow = 14 * 24 * time.Hour

// cursorUsageSessionCap bounds the per-session evidence read.
const cursorUsageSessionCap = 500

// checkCursorUsage reports recent Cursor sessions that recorded activity
// but NO token usage, grouped by the reason internal/cursorusage assigns
// from the evidence rows (prompt hooks, afterAgentResponse rows, and the
// turn / attempt rows the cursor adapter reads out of the cursor-agent
// debug log). Each reason carries the operator action that would change
// it. Read-only, like every other doctor check; the evidence columns match
// store.CursorUsageEvidence (same cursorusage row identity).
//
// wiring is the registration state of the finish hooks (stop,
// afterAgentResponse) from the same hooks.json walk the cursor.hooks check
// reports (CursorFinishHooksWiring), so a session with prompts but no
// finish hook is told to re-run `observer init --cursor` only when those
// hooks are actually not registered.
//
// Named "cursor.usage" so `observer doctor cursor` scopes to it.
func checkCursorUsage(ctx context.Context, database *sql.DB, wiring cursorusage.HookWiring) Check {
	const name = "cursor.usage"
	if database == nil {
		return Check{Name: name, Status: StatusFail, Message: "no database handle"}
	}
	cutoff := time.Now().UTC().Add(-cursorUsageWindow).Format(time.RFC3339Nano)
	ids, err := cursorSessionsWithoutUsage(ctx, database, cutoff)
	if err != nil {
		return Check{Name: name, Status: StatusFail, Message: err.Error()}
	}
	evidence, err := cursorEvidenceRows(ctx, database, ids)
	if err != nil {
		return Check{Name: name, Status: StatusFail, Message: err.Error()}
	}
	counts := map[cursorusage.Reason]int{}
	examples := map[cursorusage.Reason]string{}
	total := 0
	for _, id := range ids {
		ev := cursorusage.Tally(evidence[id])
		ev.FinishHooks = wiring
		r := cursorusage.Classify(ev)
		counts[r]++
		if examples[r] == "" {
			examples[r] = id
		}
		total++
	}
	if total == 0 {
		return Check{Name: name, Status: StatusOK, Message: "every recent Cursor session with activity has token usage (or there were none)"}
	}
	reasons := make([]cursorusage.Reason, 0, len(counts))
	for r := range counts {
		reasons = append(reasons, r)
	}
	sort.Slice(reasons, func(i, j int) bool { return counts[reasons[i]] > counts[reasons[j]] })
	var parts, details []string
	for _, r := range reasons {
		parts = append(parts, fmt.Sprintf("%d %s", counts[r], strings.ReplaceAll(string(r), "_", " ")))
		details = append(details, fmt.Sprintf("%s: %d session(s), e.g. %s - %s", r, counts[r], examples[r], cursorusage.Remedy(r)))
	}
	details = append(details, "usage for these sessions is unknown, not zero; the session page names the events that fired")
	return Check{
		Name:    name,
		Status:  StatusWarn,
		Message: fmt.Sprintf("%d Cursor session(s) in the last 14 days recorded activity but no token usage (%s)", total, strings.Join(parts, ", ")),
		Details: details,
	}
}

// cursorSessionsWithoutUsage lists recent Cursor sessions (newest first,
// capped) that recorded at least one action but no token usage.
func cursorSessionsWithoutUsage(ctx context.Context, database *sql.DB, cutoff string) ([]string, error) {
	rows, err := database.QueryContext(ctx, `
		SELECT s.id FROM sessions s
		WHERE s.tool = ? AND s.started_at >= ?
		  AND EXISTS (SELECT 1 FROM actions a WHERE a.session_id = s.id AND a.tool = ?)
		  AND NOT EXISTS (SELECT 1 FROM token_usage t WHERE t.session_id = s.id)
		ORDER BY s.started_at DESC
		LIMIT ?`, models.ToolCursor, cutoff, models.ToolCursor, cursorUsageSessionCap)
	if err != nil {
		return nil, fmt.Errorf("query cursor sessions: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan cursor sessions: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read cursor sessions: %w", err)
	}
	return ids, nil
}

// cursorEvidenceRows loads the evidence rows of the given sessions, oldest
// first per session, for cursorusage.Tally (the one owner of the row
// identity; store.CursorUsageEvidence and the org rollup run the same fold).
func cursorEvidenceRows(ctx context.Context, database *sql.DB, ids []string) (map[string][]cursorusage.Row, error) {
	out := map[string][]cursorusage.Row{}
	if len(ids) == 0 {
		return out, nil
	}
	types := cursorusage.EvidenceActionTypes
	args := make([]any, 0, len(ids)+len(types)+1)
	for _, id := range ids {
		args = append(args, id)
	}
	args = append(args, models.ToolCursor)
	for _, t := range types {
		args = append(args, t)
	}
	marks := func(n int) string { return strings.TrimRight(strings.Repeat("?,", n), ",") }
	//nolint:gosec // G202: only ?-placeholder lists are concatenated; every value binds via args.
	q := `SELECT session_id, action_type, COALESCE(source_event_id, '')
		FROM actions
		WHERE session_id IN (` + marks(len(ids)) + `) AND tool = ? AND action_type IN (` + marks(len(types)) + `)
		ORDER BY session_id, timestamp, id`
	rows, err := database.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query cursor evidence: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var sid string
		var r cursorusage.Row
		if err := rows.Scan(&sid, &r.ActionType, &r.SourceEventID); err != nil {
			return nil, fmt.Errorf("scan cursor evidence: %w", err)
		}
		out[sid] = append(out[sid], r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read cursor evidence: %w", err)
	}
	return out, nil
}
