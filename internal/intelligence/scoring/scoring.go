package scoring

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// The spec §15.2 component weights. Exported so read surfaces (the dashboard
// Quality card) render the formula from the one owner instead of a copy.
const (
	WeightRedundancy  = 0.4
	WeightError       = 0.3
	WeightExploration = 0.2
	WeightContinuity  = 0.1
)

// Scores is the per-session quality summary. A zero Scores is the correct
// value for a session with zero actions — callers shouldn't write it back.
type Scores struct {
	SessionID         string  `json:"session_id"`
	QualityScore      float64 `json:"quality_score"`
	RedundancyRatio   float64 `json:"redundancy_ratio"`
	ErrorRate         float64 `json:"error_rate"`
	ExplorationEff    float64 `json:"exploration_efficiency"`
	ContinuityScore   float64 `json:"continuity_score"`
	OnboardingCost    int64   `json:"onboarding_cost"`
	TurnsToFirstEdit  int     `json:"turns_to_first_edit"`
	RetryCostTokens   int64   `json:"retry_cost_tokens"`
	TotalActions      int     `json:"total_actions"`
	TotalFailures     int     `json:"total_failures"`
	StaleReads        int     `json:"stale_reads"`
	DistinctFilesRead int     `json:"distinct_files_read"`
	DistinctFilesEdit int     `json:"distinct_files_edited"`

	// Spec §14.1 freshness/stale-read join. Three fields are
	// *int / *float64 so sessions without cache data (Tier 3 /
	// pre-backfill / non-Anthropic providers) leave them NULL
	// in the DB rather than landing fake zeros. Populated only
	// when the session has cache_events from which to infer
	// compaction/expiry boundaries.
	//
	// StaleReadsWasteful: the prior copy still sat inside a live
	// cached prefix at re-read time AND no compaction_reset /
	// expiry_rewrite intervened. The re-read was genuinely
	// avoidable.
	//
	// StaleReadsNecessary: a compaction_reset / expiry_rewrite
	// happened between this read and the prior read of the same
	// target. The cached copy is gone; the re-read is the only
	// way to get the content back.
	//
	// RedundancyRatioWasteful: same fraction as RedundancyRatio
	// but over the wasteful subset only — the dashboard
	// "Redundancy" surface renders both side-by-side.
	StaleReadsWasteful      *int     `json:"stale_reads_wasteful,omitempty"`
	StaleReadsNecessary     *int     `json:"stale_reads_necessary,omitempty"`
	RedundancyRatioWasteful *float64 `json:"redundancy_ratio_wasteful,omitempty"`
}

// Scorer runs scoring passes against a DB.
type Scorer struct {
	db  *sql.DB
	now func() time.Time
}

// New wraps db.
func New(db *sql.DB) *Scorer {
	return &Scorer{db: db, now: func() time.Time { return time.Now().UTC() }}
}

// WithNow overrides the clock Write stamps scored_at with (tests). A nil fn
// is ignored. Returns s for chaining.
func (s *Scorer) WithNow(fn func() time.Time) *Scorer {
	if fn != nil {
		s.now = fn
	}
	return s
}

// BatchOptions parameterizes BatchScore.
type BatchOptions struct {
	// OnlyUnscored, when true, skips sessions that already have a non-NULL
	// quality_score. Scoring is idempotent, so callers that want to refresh
	// after a freshness-pipeline improvement should set this false.
	OnlyUnscored bool
	// IdleAtLeast, when non-zero, skips sessions whose latest action is
	// within this duration of now — these sessions are still "live".
	IdleAtLeast time.Duration
	// Now overrides time.Now for deterministic tests.
	Now func() time.Time
	// IDs, when non-empty, restricts the pass to these session ids (still
	// subject to OnlyUnscored / IdleAtLeast). The daemon's AutoScorer uses
	// it to re-score sessions that saw new activity since the last tick.
	IDs []string
	// Limit, when > 0, stops the pass after this many sessions were
	// attempted (scored or errored). Sessions skipped by the idle check do
	// not count — they cost one indexed query. Bounds one daemon tick so a
	// large unscored backlog is worked off over several ticks instead of in
	// one long burst.
	Limit int
}

// BatchResult summarizes a batch pass.
type BatchResult struct {
	Considered int
	Scored     int
	Skipped    int
	Errors     int
	DurationMs int64
}

// BatchScore walks the sessions table and scores each session that matches
// opts. Errors on a single session are counted but do not abort the pass.
func (s *Scorer) BatchScore(ctx context.Context, opts BatchOptions) (BatchResult, error) {
	start := time.Now()
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}

	// Sessions with no actions are never scorable (ScoreSession returns a
	// zero Scores for them), so they are filtered out here rather than
	// re-listed and skipped on every pass. Newest first, so a bounded pass
	// scores what the operator is most likely to open.
	q := `SELECT s.id FROM sessions s`
	where := []string{"EXISTS (SELECT 1 FROM actions a WHERE a.session_id = s.id)"}
	var args []any
	if opts.OnlyUnscored {
		where = append(where, "s.quality_score IS NULL")
	}
	if len(opts.IDs) > 0 {
		where = append(where, "s.id IN ("+placeholders(len(opts.IDs))+")")
		for _, id := range opts.IDs {
			args = append(args, id)
		}
	}
	q += " WHERE " + joinAnd(where) + " ORDER BY s.started_at DESC, s.id"
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return BatchResult{}, fmt.Errorf("scoring: list sessions: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return BatchResult{}, fmt.Errorf("scoring: scan session id: %w", err)
		}
		ids = append(ids, id)
	}
	rows.Close()

	res := BatchResult{Considered: len(ids)}
	cutoff := opts.Now().Add(-opts.IdleAtLeast)

	attempted := 0
	for _, id := range ids {
		if ctx.Err() != nil {
			break
		}
		if opts.Limit > 0 && attempted >= opts.Limit {
			res.Skipped++
			continue
		}
		if opts.IdleAtLeast > 0 {
			idle, err := s.sessionIdleSince(ctx, id, cutoff)
			if err != nil {
				res.Errors++
				continue
			}
			if !idle {
				res.Skipped++
				continue
			}
		}
		attempted++
		scores, err := s.ScoreSession(ctx, id)
		if err != nil {
			res.Errors++
			continue
		}
		if scores.TotalActions == 0 {
			res.Skipped++
			continue
		}
		if err := s.Write(ctx, scores); err != nil {
			res.Errors++
			continue
		}
		res.Scored++
	}
	res.DurationMs = time.Since(start).Milliseconds()
	return res, nil
}

// ScoreSession computes Scores for a single session. It does not write
// anything; callers use Write separately so tests can inspect the intermediate
// result.
func (s *Scorer) ScoreSession(ctx context.Context, sessionID string) (Scores, error) {
	out := Scores{SessionID: sessionID, TurnsToFirstEdit: -1}

	actions, err := s.loadActions(ctx, sessionID)
	if err != nil {
		return Scores{}, err
	}
	out.TotalActions = len(actions)
	if len(actions) == 0 {
		return out, nil
	}

	readsByTarget := map[string]bool{}
	editsByTarget := map[string]bool{}
	var readOrRunCount int
	var firstEditIdx int = -1
	lastFailureIdx := -1

	for i, a := range actions {
		if !a.Success {
			out.TotalFailures++
			lastFailureIdx = i
		}
		switch a.ActionType {
		case models.ActionReadFile:
			readOrRunCount++
			if a.Target != "" {
				readsByTarget[a.Target] = true
			}
			if a.Freshness == models.FreshnessStale {
				out.StaleReads++
			}
		case models.ActionEditFile, models.ActionWriteFile:
			if firstEditIdx < 0 {
				firstEditIdx = i
				out.TurnsToFirstEdit = a.TurnIndex
			}
			if a.Target != "" {
				editsByTarget[a.Target] = true
			}
		case models.ActionRunCommand:
			readOrRunCount++
		}
	}

	if readOrRunCount > 0 {
		out.RedundancyRatio = float64(out.StaleReads) / float64(readOrRunCount)
	}
	out.ErrorRate = float64(out.TotalFailures) / float64(out.TotalActions)

	// Spec §14.1 freshness/stale-read join. Pure read-side over
	// cache_events: when the session has any cache_events rows,
	// classify each stale read as wasteful (no compaction_reset /
	// expiry_rewrite intervened between this read and the prior
	// read of the same target) or necessary (a reset DID intervene
	// — the cached copy is genuinely gone). When the session has
	// no cache_events (Tier 3 / pre-backfill / non-Anthropic) the
	// three fields stay nil — no fake zeros.
	if hasCache, _ := s.sessionHasCacheEvents(ctx, sessionID); hasCache {
		wasteful, necessary := s.splitStaleReads(ctx, sessionID, actions)
		out.StaleReadsWasteful = &wasteful
		out.StaleReadsNecessary = &necessary
		if readOrRunCount > 0 {
			ratio := float64(wasteful) / float64(readOrRunCount)
			out.RedundancyRatioWasteful = &ratio
		} else {
			zero := 0.0
			out.RedundancyRatioWasteful = &zero
		}
	}

	out.DistinctFilesRead = len(readsByTarget)
	out.DistinctFilesEdit = len(editsByTarget)
	touched := len(readsByTarget)
	for k := range editsByTarget {
		if !readsByTarget[k] {
			touched++
		}
	}
	if touched > 0 {
		out.ExplorationEff = clamp01(float64(out.DistinctFilesEdit) / float64(touched))
	}

	// Continuity: sessions that run long enough to build working memory
	// score higher. A soft sigmoid on TotalActions feels about right — a
	// 1-action session is noise; a 50-action session has flow.
	out.ContinuityScore = continuityFrom(out.TotalActions)

	// Tokens-side metrics, best-effort.
	if firstEditIdx >= 0 {
		out.OnboardingCost, _ = s.sumTokensBefore(ctx, sessionID, actions[firstEditIdx].Timestamp)
	} else {
		// No edits means the whole session was onboarding — cost is total.
		out.OnboardingCost, _ = s.sumTokensBefore(ctx, sessionID, time.Time{})
	}
	if lastFailureIdx >= 0 {
		out.RetryCostTokens, _ = s.sumTokensAfterFailures(ctx, sessionID)
	}

	out.QualityScore = WeightRedundancy*(1-out.RedundancyRatio) +
		WeightError*(1-out.ErrorRate) +
		WeightExploration*out.ExplorationEff +
		WeightContinuity*out.ContinuityScore
	return out, nil
}

// Write persists scores back into the sessions row. It is the ONE writer of
// the sessions score columns (incl. migration 137's exploration_efficiency /
// continuity_score / scored_at / scored_action_count).
func (s *Scorer) Write(ctx context.Context, scores Scores) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET
		quality_score = ?, redundancy_ratio = ?, error_rate = ?,
		onboarding_cost = ?, turns_to_first_edit = ?, retry_cost_tokens = ?,
		stale_reads_wasteful = ?, stale_reads_necessary = ?,
		redundancy_ratio_wasteful = ?,
		exploration_efficiency = ?, continuity_score = ?,
		scored_at = ?, scored_action_count = ?
		WHERE id = ?`,
		scores.QualityScore, scores.RedundancyRatio, scores.ErrorRate,
		scores.OnboardingCost, nullableInt(scores.TurnsToFirstEdit),
		scores.RetryCostTokens,
		nullableIntPtr(scores.StaleReadsWasteful),
		nullableIntPtr(scores.StaleReadsNecessary),
		nullableFloat64Ptr(scores.RedundancyRatioWasteful),
		scores.ExplorationEff, scores.ContinuityScore,
		s.now().UTC().Format(time.RFC3339Nano), scores.TotalActions,
		scores.SessionID)
	if err != nil {
		return fmt.Errorf("scoring: write %s: %w", scores.SessionID, err)
	}
	return nil
}

// sessionHasCacheEvents reports whether cachetrack has seen any
// events for this session. Drives the §14.1 wasteful/necessary
// split: false → leave the three new score fields nil.
func (s *Scorer) sessionHasCacheEvents(ctx context.Context, sessionID string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM cache_events WHERE session_id = ? LIMIT 1`, sessionID).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

// splitStaleReads walks each FreshnessStale read in actions and
// classifies it as wasteful or necessary. The classifier is
// simple by design — the spec §14.1 wording is "compaction or
// expiry evicted it → not waste"; the lookup is one SQL per
// stale read but the stale-read count is small in practice
// (operators care about sessions with N≤20 stale reads; sessions
// with more are dominated by other signals).
//
// For each stale read at time t_curr on target T:
//   - Find the prior read of T in the same session at time t_prior
//     (or fall back to session start).
//   - Query cache_events for ANY row with kind IN
//     ('compaction_reset', 'expiry_rewrite') for this session
//     where timestamp ∈ [t_prior, t_curr].
//   - Match → NECESSARY. No match → WASTEFUL.
//
// A read that has no prior read of the same target (the first
// read of a file) is NOT stale, so it doesn't reach this
// function (FreshnessStale is computed on the freshness
// pipeline by comparing against a prior read).
func (s *Scorer) splitStaleReads(ctx context.Context, sessionID string, actions []models.Action) (wasteful, necessary int) {
	// The session's eviction events (compaction_reset / expiry_rewrite) are
	// loaded ONCE and each stale read is answered by a binary search, instead
	// of one cache_events query per stale read (2k stale reads x a 24k-row
	// session index scan took ~20s on a 33k-action session). A load error
	// degrades exactly like the old per-read query error did: no eviction
	// found, so the read counts as wasteful.
	evictions, _ := s.loadEvictionStamps(ctx, sessionID)
	// Index prior-read timestamps by target so each stale read is a single
	// window predicate.
	lastReadByTarget := map[string]time.Time{}
	for _, a := range actions {
		if a.ActionType != models.ActionReadFile || a.Target == "" {
			continue
		}
		if a.Freshness != models.FreshnessStale {
			lastReadByTarget[a.Target] = a.Timestamp
			continue
		}
		prior, hasPrior := lastReadByTarget[a.Target]
		if !hasPrior {
			// No prior read — shouldn't happen for FreshnessStale,
			// but defensive: count as wasteful (closest to the
			// existing behaviour where every stale read was a
			// redundancy hit).
			wasteful++
			lastReadByTarget[a.Target] = a.Timestamp
			continue
		}
		if evictedBetween(evictions, prior, a.Timestamp) {
			necessary++
		} else {
			wasteful++
		}
		lastReadByTarget[a.Target] = a.Timestamp
	}
	return wasteful, necessary
}

// loadEvictionStamps returns the session's compaction_reset / expiry_rewrite
// cache_event timestamps as stored TEXT, sorted ascending (SQLite's binary
// TEXT order, which is Go's string order).
func (s *Scorer) loadEvictionStamps(ctx context.Context, sessionID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT timestamp FROM cache_events
		  WHERE session_id = ?
		    AND kind IN ('compaction_reset', 'expiry_rewrite')
		  ORDER BY timestamp`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("scoring: eviction events: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ts string
		if err := rows.Scan(&ts); err != nil {
			return nil, fmt.Errorf("scoring: scan eviction event: %w", err)
		}
		out = append(out, ts)
	}
	return out, rows.Err()
}

// evictedBetween reports whether any eviction stamp lies in (start, end]. The
// half-open interval matches "an event after the prior read up to and
// including the current re-read." Bounds are compared as formatted TEXT, the
// same comparison the former per-read SQL predicate made. Empty window or no
// match → false.
func evictedBetween(stamps []string, start, end time.Time) bool {
	if !end.After(start) || len(stamps) == 0 {
		return false
	}
	lo := start.UTC().Format(time.RFC3339Nano)
	hi := end.UTC().Format(time.RFC3339Nano)
	// First stamp strictly greater than lo.
	i := sort.Search(len(stamps), func(i int) bool { return stamps[i] > lo })
	return i < len(stamps) && stamps[i] <= hi
}

// nullableIntPtr converts a *int into a driver.Value the SQL
// layer maps to NULL when nil. Mirrors the existing nullableInt
// helper which takes a sentinel int for "missing."
func nullableIntPtr(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

// nullableFloat64Ptr is the *float64 sibling of nullableIntPtr.
func nullableFloat64Ptr(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}

// loadActions pulls the ordered action rows the scorer needs. Minimal
// columns to keep memory flat for long sessions.
func (s *Scorer) loadActions(ctx context.Context, sessionID string) ([]models.Action, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, timestamp, turn_index, action_type, target, success,
		        COALESCE(freshness, ''), COALESCE(change_detected, 0)
		 FROM actions WHERE session_id = ? ORDER BY id`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("scoring: query actions: %w", err)
	}
	defer rows.Close()
	var out []models.Action
	for rows.Next() {
		var a models.Action
		var ts string
		var successInt, changeInt int
		if err := rows.Scan(&a.ID, &ts, &a.TurnIndex, &a.ActionType, &a.Target,
			&successInt, &a.Freshness, &changeInt); err != nil {
			return nil, fmt.Errorf("scoring: scan action: %w", err)
		}
		a.Success = successInt != 0
		a.ChangeDetected = changeInt != 0
		if parsed, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			a.Timestamp = parsed
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scoring: actions rows: %w", err)
	}
	return out, nil
}

// sumTokensBefore returns input+output tokens for token_usage rows in the
// session with timestamp < cutoff. A zero cutoff means "all rows".
func (s *Scorer) sumTokensBefore(ctx context.Context, sessionID string, cutoff time.Time) (int64, error) {
	q := `SELECT COALESCE(SUM(input_tokens), 0) + COALESCE(SUM(output_tokens), 0)
	      FROM token_usage WHERE session_id = ?`
	args := []any{sessionID}
	if !cutoff.IsZero() {
		q += ` AND timestamp < ?`
		args = append(args, cutoff.UTC().Format(time.RFC3339Nano))
	}
	var total int64
	if err := s.db.QueryRowContext(ctx, q, args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("scoring: sum tokens: %w", err)
	}
	return total, nil
}

// sumTokensAfterFailures returns input+output tokens for turns that happen
// after a failed action but within the same session. Proxy: we bucket all
// failures together and sum tokens between each failure and the next
// success. This over-estimates when the failure had nothing to do with the
// later turns, but is the simplest first-cut "retry budget" proxy.
func (s *Scorer) sumTokensAfterFailures(ctx context.Context, sessionID string) (int64, error) {
	// Find all failure timestamps for this session.
	rows, err := s.db.QueryContext(ctx,
		`SELECT timestamp FROM actions
		 WHERE session_id = ? AND success = 0 ORDER BY timestamp`, sessionID)
	if err != nil {
		return 0, fmt.Errorf("scoring: failure timestamps: %w", err)
	}
	defer rows.Close()
	var times []time.Time
	for rows.Next() {
		var ts string
		if err := rows.Scan(&ts); err != nil {
			return 0, fmt.Errorf("scoring: scan failure ts: %w", err)
		}
		if parsed, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			times = append(times, parsed)
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(times) == 0 {
		return 0, nil
	}
	// Sum token_usage rows that occur within 5 minutes after each failure.
	// Overlapping windows are OK — we only want a rough "cost of retries".
	// The session's token rows are loaded ONCE, ordered by the same TEXT
	// timestamp SQL compares, and each window is answered from a prefix sum:
	// one query per session instead of one per failure (the per-failure form
	// took ~24s on a 33k-action session with 424 failures). The window bounds
	// keep the previous SQL semantics exactly: TEXT timestamp >= start AND
	// < end, compared as strings.
	trows, err := s.db.QueryContext(ctx,
		`SELECT timestamp, COALESCE(input_tokens, 0) + COALESCE(output_tokens, 0)
		 FROM token_usage WHERE session_id = ? ORDER BY timestamp`, sessionID)
	if err != nil {
		return 0, fmt.Errorf("scoring: retry token rows: %w", err)
	}
	defer trows.Close()
	var stamps []string
	prefix := []int64{0}
	for trows.Next() {
		var ts string
		var n int64
		if err := trows.Scan(&ts, &n); err != nil {
			return 0, fmt.Errorf("scoring: scan retry token row: %w", err)
		}
		stamps = append(stamps, ts)
		prefix = append(prefix, prefix[len(prefix)-1]+n)
	}
	if err := trows.Err(); err != nil {
		return 0, fmt.Errorf("scoring: retry token rows: %w", err)
	}
	var total int64
	for _, t := range times {
		lo := sort.SearchStrings(stamps, t.UTC().Format(time.RFC3339Nano))
		hi := sort.SearchStrings(stamps, t.Add(5*time.Minute).UTC().Format(time.RFC3339Nano))
		if hi > lo {
			total += prefix[hi] - prefix[lo]
		}
	}
	return total, nil
}

// sessionIdleSince reports whether the session's latest action is older than
// cutoff (meaning the session is idle and safe to score).
func (s *Scorer) sessionIdleSince(ctx context.Context, sessionID string, cutoff time.Time) (bool, error) {
	var ts sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT MAX(timestamp) FROM actions WHERE session_id = ?`, sessionID).Scan(&ts)
	if err != nil {
		return false, fmt.Errorf("scoring: idle check: %w", err)
	}
	if !ts.Valid {
		// No actions → treat as idle; caller's score path will skip it
		// anyway since TotalActions will be 0.
		return true, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, ts.String)
	if err != nil {
		return false, fmt.Errorf("scoring: parse timestamp %q: %w", ts.String, err)
	}
	return parsed.Before(cutoff), nil
}

// continuityFrom maps TotalActions to a [0,1] continuity score. Chosen so a
// 50-action session scores ~0.88 and a 5-action session scores ~0.39.
func continuityFrom(totalActions int) float64 {
	if totalActions <= 0 {
		return 0
	}
	// 1 - exp(-n/20) gives a smooth ramp from 0 to 1, halfway around n=14.
	return clamp01(1 - math.Exp(-float64(totalActions)/20.0))
}

func clamp01(f float64) float64 {
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}

func nullableInt(n int) sql.NullInt64 {
	if n < 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(n), Valid: true}
}

// SessionsActiveBetween returns the ids of sessions with at least one action
// whose timestamp falls in (from, to]. Served by idx_actions_timestamp, so a
// daemon tick's "what saw new activity since last time" probe stays cheap on
// a large corpus. A zero or empty window returns nil.
func (s *Scorer) SessionsActiveBetween(ctx context.Context, from, to time.Time) ([]string, error) {
	if !to.After(from) {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT session_id FROM actions
		  WHERE timestamp > ? AND timestamp <= ?`,
		from.UTC().Format(time.RFC3339Nano), to.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("scoring: active sessions: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scoring: scan active session: %w", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scoring: active sessions rows: %w", err)
	}
	return out, nil
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, 0, 2*n)
	for i := 0; i < n; i++ {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, '?')
	}
	return string(b)
}

func joinAnd(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += " AND "
		}
		out += p
	}
	return out
}
