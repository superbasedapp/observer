package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/predict"
	"github.com/marmutapp/superbased-observer/internal/sessiongauge"
	"github.com/marmutapp/superbased-observer/internal/spendverdict"
)

// PredictShape is the session's assembled cost-estimate substrate — the
// raw token shape the Next-Message Cost Predictor scores. Rates are NOT
// resolved here (the dashboard/CLI caller injects them via
// cost.Table.Lookup) so this seam stays cost-package-free, mirroring the
// cachetrack-forecast split. Per the §0 findings the substrate is
// token_usage, not api_turns.
type PredictShape struct {
	Tool             string
	Model            string
	ProjectID        int64
	PrefixTokens     int64
	TurnSamples      []predict.TurnSample
	TurnsPerMessage  []int
	ObservedMessages int
}

// predictTurnRow is one row of the predictor's turn substrate: the per-turn
// union of the proxy's api_turns and the adapters' token_usage, deduped so a
// turn captured by BOTH is counted once.
//
// WHY A UNION AND NOT token_usage ALONE. The original seam read
// token_usage exclusively, on the §0 finding that it is the broader
// substrate. That silently zeroed every session the proxy captured but
// no adapter ever transcribed — e.g. a claude-code session launched from
// the dashboard terminal in a directory that has no
// ~/.claude/projects/<slug>/ transcript. Such a session has real,
// proxy-accurate api_turns rows (model, cache_read, input, output) while
// token_usage is permanently empty, so the predictor reported
// "no model observed" on a session the SAME panel was simultaneously
// rendering as 7 turns / 416K tokens / $0.25 from api_turns. That
// contradiction is the bug the union fixes.
//
// WHICH ROWS SURVIVE is the one session rule, sessionmsg.DeriveVerdicts
// (over spendverdict.LoadSession's rows) — the rule the session detail
// header on the same panel uses. It replaced a SQL `source_event_id NOT IN request_id` +
// `NOT EXISTS (same raw-output shape)` pair (lane R2-PARITY-2) that missed
// every reasoning-split twin (a codex / OpenCode transcript reports output
// NET of reasoning, the proxy GROSS) and dropped EVERY same-shape transcript
// row rather than one twin per proxy row. A twinned proxy row carries its
// twin's visible output (Output), exactly as the header's output bucket does.
type predictTurnRow struct {
	ts        string
	model     string
	input     int64
	output    int64
	cacheRead int64
}

// loadPredictTurnRows loads one session's deduped turn rows, ordered by
// timestamp (text order, the same order the SQL substrate used): the rows
// spendverdict.LoadSession loads for every node reader of a session, kept
// or dropped by sessionmsg.DeriveVerdicts - the rule the session header on
// the same panel applies (a proxy row the session-cumulative reconciliation
// dropped, and a transcript row that is a second capture, are not turns).
func loadPredictTurnRows(ctx context.Context, db *sql.DB, sessionID string) ([]predictTurnRow, error) {
	rows, err := spendverdict.LoadSession(ctx, db, sessionID)
	if err != nil {
		return nil, fmt.Errorf("predict turn rows: %w", err)
	}
	v := rows.Verdicts()
	out := make([]predictTurnRow, 0, len(rows.Proxies)+len(rows.Tokens))
	for i, p := range rows.Proxies {
		if v.ProxyCounted[i] {
			out = append(out, predictTurnRow{ts: p.Timestamp, model: p.Model, input: p.Input, output: v.ProxyOutput[i], cacheRead: p.CacheRead})
		}
	}
	for i, t := range rows.Tokens {
		if v.TokenCounted[i] {
			out = append(out, predictTurnRow{ts: t.Timestamp, model: t.Model, input: t.Input, output: t.Output, cacheRead: t.CacheRead})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ts < out[j].ts })
	return out, nil
}

// gaugeTurns maps the predictor's turn rows onto the shared gauge
// derivation's input (internal/sessiongauge), so the prefix and the model
// fallback here are the SAME arithmetic the org drawer runs.
func gaugeTurns(rows []predictTurnRow) []sessiongauge.Turn {
	out := make([]sessiongauge.Turn, 0, len(rows))
	for _, r := range rows {
		out = append(out, sessiongauge.Turn{Timestamp: r.ts, Model: r.model, Input: r.input, Output: r.output, CacheRead: r.cacheRead})
	}
	return out
}

// LoadSessionGaugeTurns returns one session's counted turn rows (the rows
// the one session rule keeps, see loadPredictTurnRows) as the context
// gauge's input. The org drawer builds the same slice from its own copy of
// the rows (rollup.loadSessionSpendTurns), so both dashboards feed
// sessiongauge.Context identical turns.
func (s *Store) LoadSessionGaugeTurns(ctx context.Context, sessionID string) ([]sessiongauge.Turn, error) {
	rows, err := loadPredictTurnRows(ctx, s.db, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadSessionGaugeTurns: %w", err)
	}
	return gaugeTurns(rows), nil
}

// LoadSessionShape assembles the predictor's per-session input from the
// deduped api_turns ∪ token_usage turn substrate (+ user_prompt action
// boundaries for the turns-per-message fan-out). Returns sql.ErrNoRows
// when the session doesn't exist.
//
//   - Model: sessions.model, falling back to the dominant turn-row model
//     (the same fallback handleSessionDetail uses, since sessions.model is
//     empty for ~89% of claude-code sessions).
//   - PrefixTokens (P "now"): the most-recent turn's cache_read_tokens —
//     the running cache prefix re-read every turn. 0 for an uncached
//     provider.
//   - TurnSamples: per-turn (fresh-input, output) over the session's turn
//     rows. Fresh = max(input − cache_read, 0).
//   - TurnsPerMessage / ObservedMessages: agent turns bucketed between
//     consecutive user_prompt timestamps (only messages with ≥1 captured
//     turn). Empty when the session has no user_prompt actions.
func (s *Store) LoadSessionShape(ctx context.Context, sessionID string) (PredictShape, error) {
	var shape PredictShape

	var model sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT tool, COALESCE(model, ''), project_id FROM sessions WHERE id = ?`, sessionID).
		Scan(&shape.Tool, &model, &shape.ProjectID)
	if err != nil {
		return shape, err
	}
	shape.Model = model.String

	turns, err := loadPredictTurnRows(ctx, s.db, sessionID)
	if err != nil {
		return shape, err
	}

	// Model fallback: dominant turn-row model by token volume, and P "now"
	// (the latest non-zero cache_read prefix), both through the shared
	// gauge derivation so the org drawer computes the same numbers.
	gt := gaugeTurns(turns)
	if shape.Model == "" {
		shape.Model = sessiongauge.DominantModel(gt)
	}
	shape.PrefixTokens = sessiongauge.LatestPrefix(gt)

	// Per-turn (fresh-input, output) samples + the turn timestamps used
	// for the user-message bucketing.
	turnTimes, samples := turnSamples(turns)
	shape.TurnSamples = samples

	// Turns-per-message fan-out. An EXACT grouping wins: when the client
	// tagged its proxied requests with a prompt id (api_turns.prompt_id,
	// migration 139), each distinct id is one user message. Otherwise fall
	// back to bucketing turn timestamps between user_prompt actions.
	byPromptID, err := loadPromptIDFanOut(ctx, s.db, sessionID)
	if err != nil {
		return shape, err
	}
	if len(byPromptID) > 0 {
		shape.TurnsPerMessage = byPromptID
	} else {
		promptTimes, err := loadUserPromptTimes(ctx, s.db, sessionID)
		if err != nil {
			return shape, err
		}
		shape.TurnsPerMessage = bucketTurnsPerMessage(promptTimes, turnTimes)
	}
	shape.ObservedMessages = len(shape.TurnsPerMessage)

	return shape, nil
}

// promptTurnFilter selects the api_turns rows that count toward a prompt's
// fan-out: tagged with a prompt id and carrying usage (the same "no input
// and no output is not a turn" rule loadTurnSamples applies).
const promptTurnFilter = `prompt_id IS NOT NULL AND prompt_id != ''
	AND (COALESCE(input_tokens, 0) > 0 OR COALESCE(output_tokens, 0) > 0)`

// loadPromptIDFanOut returns the session's per-user-message turn counts
// from the proxy's prompt-id tags, one entry per distinct prompt id in
// first-seen order. Empty when no proxied turn carried a prompt id.
func loadPromptIDFanOut(ctx context.Context, db *sql.DB, sessionID string) ([]int, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT COUNT(*) FROM api_turns
		 WHERE session_id = ? AND `+promptTurnFilter+`
		 GROUP BY prompt_id
		 ORDER BY MIN(timestamp) ASC, prompt_id ASC`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("prompt-id fan-out: %w", err)
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var n int
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("scan prompt-id fan-out: %w", err)
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("prompt-id fan-out rows: %w", err)
	}
	return out, nil
}

// turnSamples returns, in time order, the parsed turn timestamps (for
// bucketing) and the (fresh-input, output) samples of the session's deduped
// turn rows. Rows with no input and no output are skipped.
func turnSamples(rows []predictTurnRow) ([]time.Time, []predict.TurnSample) {
	var times []time.Time
	var samples []predict.TurnSample
	for _, r := range rows {
		if r.input == 0 && r.output == 0 {
			continue
		}
		fresh := r.input - r.cacheRead
		if fresh < 0 {
			fresh = 0
		}
		samples = append(samples, predict.TurnSample{FreshInput: fresh, Output: r.output})
		if t, ok := parseDBTime(r.ts); ok {
			times = append(times, t)
		}
	}
	return times, samples
}

// loadUserPromptTimes returns the session's user_prompt action timestamps
// in ascending order — the user-message boundaries.
func loadUserPromptTimes(ctx context.Context, db *sql.DB, sessionID string) ([]time.Time, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT timestamp FROM actions
		 WHERE session_id = ? AND action_type = 'user_prompt'
		 ORDER BY timestamp ASC`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("user_prompt times: %w", err)
	}
	defer rows.Close()
	var out []time.Time
	for rows.Next() {
		var ts string
		if err := rows.Scan(&ts); err != nil {
			return nil, fmt.Errorf("scan user_prompt: %w", err)
		}
		if t, ok := parseDBTime(ts); ok {
			out = append(out, t)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("user_prompt rows: %w", err)
	}
	return out, nil
}

// bucketTurnsPerMessage counts turn timestamps falling into each
// [prompt[i], prompt[i+1]) interval (the last interval runs to +∞).
// Only intervals with ≥1 turn are returned, so the result is the
// observed fan-out distribution (a prompt with no captured turns is
// noise, not a zero-cost message). Empty prompts → empty result.
func bucketTurnsPerMessage(prompts, turns []time.Time) []int {
	if len(prompts) == 0 || len(turns) == 0 {
		return nil
	}
	sort.Slice(prompts, func(i, j int) bool { return prompts[i].Before(prompts[j]) })
	sort.Slice(turns, func(i, j int) bool { return turns[i].Before(turns[j]) })

	counts := make([]int, len(prompts))
	ti := 0
	// Skip turns before the first prompt (pre-session noise / system).
	for ti < len(turns) && turns[ti].Before(prompts[0]) {
		ti++
	}
	for i := 0; i < len(prompts); i++ {
		var end time.Time
		hasEnd := i+1 < len(prompts)
		if hasEnd {
			end = prompts[i+1]
		}
		for ti < len(turns) && (!hasEnd || turns[ti].Before(end)) {
			counts[i]++
			ti++
		}
	}
	out := make([]int, 0, len(counts))
	for _, c := range counts {
		if c >= 1 {
			out = append(out, c)
		}
	}
	return out
}

// LoadToolProjectPrior returns the cross-session turns-per-message prior
// for (tool, projectID) — the tier-2 fallback when the current session
// has no user_prompt boundaries. Each sample is one comparable session's
// average turns-per-user-message (turn rows ÷ user_prompt count), a cheap
// approximation that avoids per-session bucketing across the corpus.
//
// Scopes to the project first; widens to the tool when the project yields
// fewer than 3 comparable sessions. windowDays bounds recency (0 = no
// bound). Returns nil when no comparable session carries user_prompt
// boundaries (caller then falls to the static default).
func (s *Store) LoadToolProjectPrior(ctx context.Context, tool string, projectID int64, windowDays int) ([]int, error) {
	prior, err := s.loadPriorScoped(ctx, tool, projectID, windowDays)
	if err != nil {
		return nil, err
	}
	if len(prior) < minPriorSessions {
		// Widen to tool-wide.
		wide, werr := s.loadPriorScoped(ctx, tool, 0, windowDays)
		if werr != nil {
			return nil, werr
		}
		if len(wide) > len(prior) {
			prior = wide
		}
	}
	// Min-sample guard: a prior built from one or two sessions yields
	// meaningless quantiles (and, on a retention-pruned DB where most
	// sessions have lost their user_prompt boundaries, an inflated
	// token_turns/user_prompt ratio → a flat, wrong band). Below the
	// floor, return nil so the estimator falls to its static default
	// tier rather than labelling a 1-session guess as a "prior".
	if len(prior) < minPriorSessions {
		return nil, nil
	}
	return prior, nil
}

// minPriorSessions is the floor for trusting the cross-session T prior.
// Below it the quantiles aren't meaningful; the estimator uses the
// static default fan-out instead.
const minPriorSessions = 3

func (s *Store) loadPriorScoped(ctx context.Context, tool string, projectID int64, windowDays int) ([]int, error) {
	args := []any{tool}
	// A comparable session's turn count is its DEDUPLICATED turn rows - the
	// api_turns and token_usage rows the stored sessionmsg dedup verdicts
	// count (internal/spendverdict), each with some input or output - which
	// is exactly the turn set LoadSessionShape samples for the session
	// itself (loadPredictTurnRows + turnSamples). It replaced a
	// MAX(COUNT(token_usage), COUNT(api_turns)) approximation (lane
	// R2-ONERULE) that counted a proxied session's turns the proxy missed or
	// the transcript missed as absent, and every output-only shadow row as a
	// turn.
	//
	// A session whose proxied turns carry prompt ids (migration 139) uses
	// the exact ratio instead: tagged turns ÷ distinct prompt ids. That also
	// admits prompt-id sessions with no user_prompt actions into the prior.
	s.refreshSpendVerdictsBounded(ctx)
	//nolint:gosec // G202: the verdict fragments are closed constant SQL; values bind via args.
	q := `
		SELECT CASE
		         WHEN EXISTS (SELECT 1 FROM api_turns p WHERE p.session_id = s.id AND ` + promptTurnFilter + `)
		         THEN CAST(ROUND(
		           (SELECT COUNT(*) FROM api_turns p WHERE p.session_id = s.id AND ` + promptTurnFilter + `) * 1.0 /
		           (SELECT COUNT(DISTINCT prompt_id) FROM api_turns p WHERE p.session_id = s.id AND ` + promptTurnFilter + `)
		         ) AS INTEGER)
		         ELSE CAST(ROUND(
		           ((SELECT COUNT(*) FROM api_turns t WHERE t.session_id = s.id
		               AND ` + spendverdict.CountedProxyRowOf("t") + `
		               AND (COALESCE(t.input_tokens, 0) > 0 OR ` + spendverdict.ProxyOutputOf("t") + ` > 0))
		            + (SELECT COUNT(*) FROM token_usage k WHERE k.session_id = s.id
		               AND ` + spendverdict.CountedTokenRow("k") + `
		               AND (COALESCE(k.input_tokens, 0) > 0 OR COALESCE(k.output_tokens, 0) > 0))) * 1.0 /
		           (SELECT COUNT(*) FROM actions a WHERE a.session_id = s.id AND a.action_type = 'user_prompt')
		         ) AS INTEGER)
		       END AS avg_t
		  FROM sessions s
		 WHERE s.tool = ?
		   AND (EXISTS (SELECT 1 FROM actions a WHERE a.session_id = s.id AND a.action_type = 'user_prompt')
		        OR EXISTS (SELECT 1 FROM api_turns p WHERE p.session_id = s.id AND ` + promptTurnFilter + `))
		   AND (EXISTS (SELECT 1 FROM token_usage k WHERE k.session_id = s.id)
		        OR EXISTS (SELECT 1 FROM api_turns t WHERE t.session_id = s.id))`
	if projectID > 0 {
		q += ` AND s.project_id = ?`
		args = append(args, projectID)
	}
	if windowDays > 0 {
		q += ` AND s.started_at >= datetime('now', ?)`
		args = append(args, fmt.Sprintf("-%d days", windowDays))
	}
	q += ` ORDER BY s.started_at DESC LIMIT 100`

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("prior scoped: %w", err)
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var t sql.NullInt64
		if err := rows.Scan(&t); err != nil {
			return nil, fmt.Errorf("scan prior: %w", err)
		}
		if t.Valid && t.Int64 >= 1 {
			out = append(out, int(t.Int64))
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("prior rows: %w", err)
	}
	return out, nil
}

// InsertLimitSnapshot persists one rate-limit observation (migration 049,
// NODE-LOCAL). The only writer of limit_snapshots — per the one-owner
// rule. Nil optional fields become NULL columns.
func (s *Store) InsertLimitSnapshot(ctx context.Context, snap models.LimitSnapshot) error {
	_, err := s.db.ExecContext(
		ctx, `
		INSERT INTO limit_snapshots
		  (scope_hash, provider, session_id, observed_at,
		   window_5h_util, window_5h_reset, window_7d_util, window_7d_reset,
		   req_limit, req_remaining, req_reset, tok_limit, tok_remaining, tok_reset,
		   status, raw)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		snap.ScopeHash, snap.Provider, nullStr(snap.SessionID), snap.ObservedAt.Unix(),
		nullF(snap.Window5hUtil), nullI(snap.Window5hReset), nullF(snap.Window7dUtil), nullI(snap.Window7dReset),
		nullI(snap.ReqLimit), nullI(snap.ReqRemaining), nullI(snap.ReqReset),
		nullI(snap.TokLimit), nullI(snap.TokRemaining), nullI(snap.TokReset),
		nullStr(snap.Status), nullStr(snap.Raw),
	)
	if err != nil {
		return fmt.Errorf("store.InsertLimitSnapshot: %w", err)
	}
	return nil
}

// LatestLimitSnapshot returns the most-recent snapshot for (scopeHash,
// provider), or ok=false when none exists. Indexed by
// idx_limit_snapshots_scope.
func (s *Store) LatestLimitSnapshot(ctx context.Context, scopeHash, provider string) (models.LimitSnapshot, bool, error) {
	var snap models.LimitSnapshot
	var observedUnix int64
	var w5u, w7u sql.NullFloat64
	var w5r, w7r, rl, rr, rrst, tl, tr, trst sql.NullInt64
	var sid, status, raw sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT id, scope_hash, provider, session_id, observed_at,
		       window_5h_util, window_5h_reset, window_7d_util, window_7d_reset,
		       req_limit, req_remaining, req_reset, tok_limit, tok_remaining, tok_reset,
		       status, raw
		  FROM limit_snapshots
		 WHERE scope_hash = ? AND provider = ?
		 ORDER BY observed_at DESC, id DESC LIMIT 1`, scopeHash, provider).
		Scan(&snap.ID, &snap.ScopeHash, &snap.Provider, &sid, &observedUnix,
			&w5u, &w5r, &w7u, &w7r, &rl, &rr, &rrst, &tl, &tr, &trst, &status, &raw)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return snap, false, nil
		}
		return snap, false, fmt.Errorf("store.LatestLimitSnapshot: %w", err)
	}
	snap.ObservedAt = time.Unix(observedUnix, 0).UTC()
	snap.SessionID = sid.String
	snap.Status = status.String
	snap.Raw = raw.String
	snap.Window5hUtil = fptr(w5u)
	snap.Window7dUtil = fptr(w7u)
	snap.Window5hReset = iptr(w5r)
	snap.Window7dReset = iptr(w7r)
	snap.ReqLimit, snap.ReqRemaining, snap.ReqReset = iptr(rl), iptr(rr), iptr(rrst)
	snap.TokLimit, snap.TokRemaining, snap.TokReset = iptr(tl), iptr(tr), iptr(trst)
	return snap, true, nil
}

// LatestLimitSnapshotForTool returns the most-recent snapshot for
// `provider` whose source session belongs to `tool`, or ok=false when
// that tool has never observed a window. This attributes the gauge to
// the credential that actually produced it: the unified 5h/weekly
// subscription windows come only from a tool whose proxied traffic
// carried those headers (Claude Code's subscription OAuth), so a tool
// like cline-cli — which routes a different credential and emits none —
// no longer inherits another tool's window. Distinct from the raw
// scope+provider LatestLimitSnapshot read; the deeper per-credential
// scope_hash derivation stays the R4 follow-up. Snapshots with no
// session_id (early stragglers) don't join and are correctly skipped.
func (s *Store) LatestLimitSnapshotForTool(ctx context.Context, provider, tool string) (models.LimitSnapshot, bool, error) {
	var snap models.LimitSnapshot
	var observedUnix int64
	var w5u, w7u sql.NullFloat64
	var w5r, w7r, rl, rr, rrst, tl, tr, trst sql.NullInt64
	var sid, status, raw sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT l.id, l.scope_hash, l.provider, l.session_id, l.observed_at,
		       l.window_5h_util, l.window_5h_reset, l.window_7d_util, l.window_7d_reset,
		       l.req_limit, l.req_remaining, l.req_reset, l.tok_limit, l.tok_remaining, l.tok_reset,
		       l.status, l.raw
		  FROM limit_snapshots l
		  JOIN sessions s ON s.id = l.session_id
		 WHERE l.provider = ? AND s.tool = ?
		 ORDER BY l.observed_at DESC, l.id DESC LIMIT 1`, provider, tool).
		Scan(&snap.ID, &snap.ScopeHash, &snap.Provider, &sid, &observedUnix,
			&w5u, &w5r, &w7u, &w7r, &rl, &rr, &rrst, &tl, &tr, &trst, &status, &raw)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return snap, false, nil
		}
		return snap, false, fmt.Errorf("store.LatestLimitSnapshotForTool: %w", err)
	}
	snap.ObservedAt = time.Unix(observedUnix, 0).UTC()
	snap.SessionID = sid.String
	snap.Status = status.String
	snap.Raw = raw.String
	snap.Window5hUtil = fptr(w5u)
	snap.Window7dUtil = fptr(w7u)
	snap.Window5hReset = iptr(w5r)
	snap.Window7dReset = iptr(w7r)
	snap.ReqLimit, snap.ReqRemaining, snap.ReqReset = iptr(rl), iptr(rr), iptr(rrst)
	snap.TokLimit, snap.TokRemaining, snap.TokReset = iptr(tl), iptr(tr), iptr(trst)
	return snap, true, nil
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullF(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}

func nullI(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

func fptr(n sql.NullFloat64) *float64 {
	if !n.Valid {
		return nil
	}
	v := n.Float64
	return &v
}

func iptr(n sql.NullInt64) *int64 {
	if !n.Valid {
		return nil
	}
	v := n.Int64
	return &v
}

// parseDBTime parses the RFC3339(Nano) timestamps the store writes.
// Returns ok=false on an unparseable value so the caller can skip it.
func parseDBTime(s string) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	return time.Time{}, false
}
