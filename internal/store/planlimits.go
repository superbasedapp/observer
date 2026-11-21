package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/planlimits"
	"github.com/marmutapp/superbased-observer/internal/spendverdict"
)

// planlimits.go is the ONE store seam of the Plans & limits module
// (docs/plans-and-limits.md): the only writer of the NODE-LOCAL plan_*
// tables (agent migrations 163 and 248) and the only SQL that reads the
// passive signals the module reuses READ-ONLY (limit_snapshots, the codex
// rate_limit actions, tool_account_observations, and the deduplicated
// token_usage / api_turns substrate for the daily usage reconciliation).
// None of it is selected by orgpush.go (tests/invariant/privacy_test.go).

// ErrPlanAccountNotFound is returned for an unknown account id.
var ErrPlanAccountNotFound = errors.New("store: plan account not found")

// PlanAccountRow is one plan_accounts row. Params are non-secret only;
// SecretKeys names which secrets the keychain holds, never a value.
type PlanAccountRow struct {
	ID         string
	Provider   string
	Source     string
	Label      string
	Params     map[string]string
	SecretKeys []string
	Enabled    bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
	State      planlimits.RunState
	LastRunAt  time.Time
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func timeOrZero(sec int64) time.Time {
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}

// InsertPlanAccount adds an account.
func (s *Store) InsertPlanAccount(ctx context.Context, a PlanAccountRow) error {
	params, err := json.Marshal(nonNilParams(a.Params))
	if err != nil {
		return fmt.Errorf("store.InsertPlanAccount: %w", err)
	}
	now := time.Now().UTC()
	if a.CreatedAt.IsZero() {
		a.CreatedAt = now
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO plan_accounts (id, provider, source, label, params, secret_keys, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.Provider, a.Source, a.Label, string(params), strings.Join(a.SecretKeys, ","), boolInt(a.Enabled),
		a.CreatedAt.Unix(), now.Unix())
	if err != nil {
		return fmt.Errorf("store.InsertPlanAccount: %w", err)
	}
	return nil
}

func nonNilParams(p map[string]string) map[string]string {
	if p == nil {
		return map[string]string{}
	}
	return p
}

const planAccountCols = `id, provider, source, label, params, secret_keys, enabled, created_at, updated_at,
	run_status, failures, shape_failures, next_due, stopped, last_run_at`

func scanPlanAccount(sc interface{ Scan(...any) error }) (PlanAccountRow, error) {
	var a PlanAccountRow
	var params, keys string
	var enabled, stopped int
	var created, updated, nextDue, lastRun int64
	if err := sc.Scan(&a.ID, &a.Provider, &a.Source, &a.Label, &params, &keys, &enabled, &created, &updated,
		&a.State.Status, &a.State.Failures, &a.State.ShapeFailures, &nextDue, &stopped, &lastRun); err != nil {
		return a, err
	}
	a.Params = map[string]string{}
	_ = json.Unmarshal([]byte(params), &a.Params)
	if keys != "" {
		a.SecretKeys = strings.Split(keys, ",")
	}
	a.Enabled = enabled != 0
	a.CreatedAt, a.UpdatedAt = timeOrZero(created), timeOrZero(updated)
	a.State.NextDue = timeOrZero(nextDue)
	a.State.Stopped = stopped != 0
	a.LastRunAt = timeOrZero(lastRun)
	return a, nil
}

// PlanAccounts lists every account, oldest first.
func (s *Store) PlanAccounts(ctx context.Context) ([]PlanAccountRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+planAccountCols+` FROM plan_accounts ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("store.PlanAccounts: %w", err)
	}
	defer rows.Close()
	var out []PlanAccountRow
	for rows.Next() {
		a, err := scanPlanAccount(rows)
		if err != nil {
			return nil, fmt.Errorf("store.PlanAccounts: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// PlanAccount returns one account or ErrPlanAccountNotFound.
func (s *Store) PlanAccount(ctx context.Context, id string) (PlanAccountRow, error) {
	a, err := scanPlanAccount(s.db.QueryRowContext(ctx, `SELECT `+planAccountCols+` FROM plan_accounts WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrPlanAccountNotFound
	}
	if err != nil {
		return a, fmt.Errorf("store.PlanAccount: %w", err)
	}
	return a, nil
}

// UpdatePlanAccountState records the outcome of one poll.
func (s *Store) UpdatePlanAccountState(ctx context.Context, id string, st planlimits.RunState, ranAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE plan_accounts SET run_status = ?, failures = ?, shape_failures = ?, next_due = ?, stopped = ?, last_run_at = ?
		 WHERE id = ?`,
		st.Status, st.Failures, st.ShapeFailures, unixOrZero(st.NextDue), boolInt(st.Stopped), unixOrZero(ranAt), id)
	if err != nil {
		return fmt.Errorf("store.UpdatePlanAccountState: %w", err)
	}
	return nil
}

// UpdatePlanAccount changes the label, params, stored secret names and the
// enabled flag, and clears a stopped poll so the next tick retries.
func (s *Store) UpdatePlanAccount(ctx context.Context, a PlanAccountRow) error {
	params, err := json.Marshal(nonNilParams(a.Params))
	if err != nil {
		return fmt.Errorf("store.UpdatePlanAccount: %w", err)
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE plan_accounts SET label = ?, params = ?, secret_keys = ?, enabled = ?, updated_at = ?,
		       stopped = 0, failures = 0, shape_failures = 0, next_due = 0
		 WHERE id = ?`,
		a.Label, string(params), strings.Join(a.SecretKeys, ","), boolInt(a.Enabled), time.Now().UTC().Unix(), a.ID)
	if err != nil {
		return fmt.Errorf("store.UpdatePlanAccount: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrPlanAccountNotFound
	}
	return nil
}

// DeletePlanAccount removes an account with its snapshots, runs and daily
// usage rows, in one transaction. The caller deletes the keychain secrets first.
func (s *Store) DeletePlanAccount(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.DeletePlanAccount: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `DELETE FROM plan_accounts WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store.DeletePlanAccount: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrPlanAccountNotFound
	}
	for _, q := range []string{
		`DELETE FROM plan_snapshots WHERE account_id = ?`,
		`DELETE FROM plan_runs WHERE account_id = ?`,
		`DELETE FROM plan_usage_daily WHERE account_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return fmt.Errorf("store.DeletePlanAccount: %w", err)
		}
	}
	return tx.Commit()
}

// InsertPlanSnapshot stores one observation. accountID is "" for the status
// line feed; sessionID is "" for a polled account.
func (s *Store) InsertPlanSnapshot(ctx context.Context, accountID, sessionID string, snap planlimits.Snapshot) error {
	body, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("store.InsertPlanSnapshot: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO plan_snapshots (account_id, provider, source, session_id, observed_at, status, body)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		nullStr(accountID), snap.Provider, snap.Source, nullStr(sessionID), snap.ObservedAt.Unix(), snap.Status, string(body))
	if err != nil {
		return fmt.Errorf("store.InsertPlanSnapshot: %w", err)
	}
	return nil
}

func decodePlanSnapshot(body string) (planlimits.Snapshot, bool) {
	var s planlimits.Snapshot
	if json.Unmarshal([]byte(body), &s) != nil || s.Provider == "" {
		return s, false
	}
	return s, true
}

// LatestPlanSnapshots returns the newest snapshot of every account.
func (s *Store) LatestPlanSnapshots(ctx context.Context) (map[string]planlimits.Snapshot, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT p.account_id, p.body FROM plan_snapshots p
		  JOIN (SELECT MAX(id) id FROM plan_snapshots WHERE account_id IS NOT NULL GROUP BY account_id) m ON m.id = p.id`)
	if err != nil {
		return nil, fmt.Errorf("store.LatestPlanSnapshots: %w", err)
	}
	defer rows.Close()
	out := map[string]planlimits.Snapshot{}
	for rows.Next() {
		var id, body string
		if err := rows.Scan(&id, &body); err != nil {
			return nil, fmt.Errorf("store.LatestPlanSnapshots: %w", err)
		}
		if snap, ok := decodePlanSnapshot(body); ok {
			out[id] = snap
		}
	}
	return out, rows.Err()
}

// PlanSnapshotHistory returns an account's snapshots since a time, oldest
// first, capped.
func (s *Store) PlanSnapshotHistory(ctx context.Context, accountID string, since time.Time, limit int) ([]planlimits.Snapshot, error) {
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT body FROM (SELECT id, body FROM plan_snapshots WHERE account_id = ? AND observed_at >= ?
		 ORDER BY observed_at DESC, id DESC LIMIT ?) ORDER BY id`, accountID, since.Unix(), limit)
	if err != nil {
		return nil, fmt.Errorf("store.PlanSnapshotHistory: %w", err)
	}
	defer rows.Close()
	var out []planlimits.Snapshot
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			return nil, fmt.Errorf("store.PlanSnapshotHistory: %w", err)
		}
		if snap, ok := decodePlanSnapshot(body); ok {
			out = append(out, snap)
		}
	}
	return out, rows.Err()
}

// PlanRunRow is one poll attempt: codes only.
type PlanRunRow struct {
	AccountID string
	StartedAt time.Time
	EndedAt   time.Time
	Outcome   string
	Detail    string
}

// maxPlanRunDetail caps the stored error class.
const maxPlanRunDetail = 200

// InsertPlanRun records one poll attempt. Detail must already be scrubbed by
// the caller; it is capped here.
func (s *Store) InsertPlanRun(ctx context.Context, r PlanRunRow) error {
	d := r.Detail
	if len(d) > maxPlanRunDetail {
		d = d[:maxPlanRunDetail]
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO plan_runs (account_id, started_at, ended_at, outcome, detail) VALUES (?, ?, ?, ?, ?)`,
		r.AccountID, r.StartedAt.Unix(), r.EndedAt.Unix(), r.Outcome, d)
	if err != nil {
		return fmt.Errorf("store.InsertPlanRun: %w", err)
	}
	return nil
}

// RecentPlanRuns returns an account's newest runs.
func (s *Store) RecentPlanRuns(ctx context.Context, accountID string, limit int) ([]PlanRunRow, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `SELECT account_id, started_at, ended_at, outcome, detail FROM plan_runs
		WHERE account_id = ? ORDER BY started_at DESC, id DESC LIMIT ?`, accountID, limit)
	if err != nil {
		return nil, fmt.Errorf("store.RecentPlanRuns: %w", err)
	}
	defer rows.Close()
	var out []PlanRunRow
	for rows.Next() {
		var r PlanRunRow
		var st, en int64
		if err := rows.Scan(&r.AccountID, &st, &en, &r.Outcome, &r.Detail); err != nil {
			return nil, fmt.Errorf("store.RecentPlanRuns: %w", err)
		}
		r.StartedAt, r.EndedAt = timeOrZero(st), timeOrZero(en)
		out = append(out, r)
	}
	return out, rows.Err()
}

// PlanOptIns returns the providers whose experimental switch is on.
func (s *Store) PlanOptIns(ctx context.Context) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT provider FROM plan_optins`)
	if err != nil {
		return nil, fmt.Errorf("store.PlanOptIns: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, fmt.Errorf("store.PlanOptIns: %w", err)
		}
		out[p] = true
	}
	return out, rows.Err()
}

// SetPlanOptIn turns a provider's experimental switch on or off.
func (s *Store) SetPlanOptIn(ctx context.Context, provider string, on bool) error {
	var err error
	if on {
		_, err = s.db.ExecContext(ctx, `INSERT INTO plan_optins (provider, enabled_at) VALUES (?, ?)
			ON CONFLICT(provider) DO NOTHING`, provider, time.Now().UTC().Unix())
	} else {
		_, err = s.db.ExecContext(ctx, `DELETE FROM plan_optins WHERE provider = ?`, provider)
	}
	if err != nil {
		return fmt.Errorf("store.SetPlanOptIn: %w", err)
	}
	return nil
}

// PrunePlanHistory deletes snapshots and runs older than before, always
// keeping each account's newest snapshot and each session's newest status
// line reading.
func (s *Store) PrunePlanHistory(ctx context.Context, before time.Time) (int64, error) {
	cut := before.Unix()
	var total int64
	for _, q := range []string{
		`DELETE FROM plan_snapshots WHERE observed_at < ? AND id NOT IN (
			SELECT MAX(id) FROM plan_snapshots WHERE account_id IS NOT NULL GROUP BY account_id)`,
		`DELETE FROM plan_runs WHERE started_at < ?`,
	} {
		res, err := s.db.ExecContext(ctx, q, cut)
		if err != nil {
			return total, fmt.Errorf("store.PrunePlanHistory: %w", err)
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

// --- Daily usage reconciliation (agent migration 248) ---------------------------

// UpsertPlanUsageDaily stores the daily totals one reading carried for an
// account. The latest value for a day wins; a day absent from this reading
// keeps its stored row (a vendor that trims its history never erases ours).
// One transaction per reading.
func (s *Store) UpsertPlanUsageDaily(ctx context.Context, accountID, provider string, days []planlimits.UsageDay, fetchedAt time.Time) error {
	if accountID == "" || len(days) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.UpsertPlanUsageDaily: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO plan_usage_daily (account_id, provider, day, tokens, fetched_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(account_id, day) DO UPDATE SET provider = excluded.provider, tokens = excluded.tokens,
		       fetched_at = excluded.fetched_at`)
	if err != nil {
		return fmt.Errorf("store.UpsertPlanUsageDaily: %w", err)
	}
	defer stmt.Close()
	at := fetchedAt.UTC().Unix()
	for _, d := range days {
		if _, err := stmt.ExecContext(ctx, accountID, provider, d.Day, d.Tokens, at); err != nil {
			return fmt.Errorf("store.UpsertPlanUsageDaily: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.UpsertPlanUsageDaily: %w", err)
	}
	return nil
}

// PlanUsageDaily returns an account's stored daily totals for the inclusive
// day window [from, to] (YYYY-MM-DD), oldest first, with the time of the
// newest reading that wrote any of the account's rows (zero when it has
// none at all).
func (s *Store) PlanUsageDaily(ctx context.Context, accountID, from, to string) ([]planlimits.UsageDay, time.Time, error) {
	var last sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(fetched_at) FROM plan_usage_daily WHERE account_id = ?`, accountID).Scan(&last); err != nil {
		return nil, time.Time{}, fmt.Errorf("store.PlanUsageDaily: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT day, tokens FROM plan_usage_daily
		WHERE account_id = ? AND day >= ? AND day <= ? ORDER BY day`, accountID, from, to)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("store.PlanUsageDaily: %w", err)
	}
	defer rows.Close()
	out := []planlimits.UsageDay{}
	for rows.Next() {
		var d planlimits.UsageDay
		if err := rows.Scan(&d.Day, &d.Tokens); err != nil {
			return nil, time.Time{}, fmt.Errorf("store.PlanUsageDaily: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, time.Time{}, fmt.Errorf("store.PlanUsageDaily: %w", err)
	}
	return out, timeOrZero(last.Int64), nil
}

// CapturedToolTokensByDay returns the tokens this node captured for sessions
// of the given tools, per UTC day (YYYY-MM-DD) in the inclusive window
// [from, to]. It reads the same deduplicated substrate the spend windows use
// (spendUnionRecordedSQL's rows: the stored sessionmsg verdicts, so a turn
// seen by both the proxy and the transcript counts once) and adds every
// token class the vendor's daily total counts: input + cache read + output +
// reasoning. Observer stores input NET of cache reads on both arms, and a
// token_usage row's output NET of its reasoning (agent migration 058), so
// the sum is the gross total the OpenAI usage object reports. Cache
// creation is not added (OpenAI reports none). Read-only.
func (s *Store) CapturedToolTokensByDay(ctx context.Context, tools []string, from, to string) (map[string]int64, error) {
	out := map[string]int64{}
	if len(tools) == 0 {
		return out, nil
	}
	start, err := time.Parse(planlimits.UsageDayLayout, from)
	if err != nil {
		return nil, fmt.Errorf("store.CapturedToolTokensByDay: from: %w", err)
	}
	s.refreshSpendVerdictsBounded(ctx)
	// The stored timestamps are compared as text, so the lower bound leaves a
	// day of margin for a row written with a non-UTC offset; date() then
	// normalises every row to its UTC day.
	floor := timestamp(start.Add(-24 * time.Hour))
	args := []any{floor, floor}
	for _, t := range tools {
		args = append(args, t)
	}
	args = append(args, from, to)
	//nolint:gosec // G202: the SQL is closed constant fragments and the IN list is placeholders; values bind via args.
	q := `SELECT date(u.ts) d, SUM(u.t) FROM (
		SELECT tu.session_id sid, tu.timestamp ts,
		       COALESCE(tu.input_tokens, 0) + COALESCE(tu.cache_read_tokens, 0) + COALESCE(tu.output_tokens, 0)
		         + COALESCE(tu.reasoning_tokens, 0) t
		  FROM token_usage tu
		 WHERE tu.timestamp >= ? AND ` + spendverdict.CountedTokenRow("tu") + `
		UNION ALL
		SELECT COALESCE(a.session_id, '') sid, a.timestamp ts,
		       COALESCE(a.input_tokens, 0) + COALESCE(a.cache_read_tokens, 0) + ` + spendverdict.ProxyOutput("a") + `
		         + ` + spendverdict.ProxyReasoning() + ` t
		  FROM api_turns a` + spendverdict.ProxyVerdictJoin("a") + `
		 WHERE a.timestamp >= ? AND ` + spendverdict.CountedProxyRow() + `
	) u JOIN sessions s ON s.id = u.sid
	 WHERE s.tool IN (` + placeholders(len(tools)) + `) AND date(u.ts) >= ? AND date(u.ts) <= ?
	 GROUP BY d`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store.CapturedToolTokensByDay: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var d sql.NullString
		var n sql.NullInt64
		if err := rows.Scan(&d, &n); err != nil {
			return nil, fmt.Errorf("store.CapturedToolTokensByDay: %w", err)
		}
		if d.Valid && n.Int64 > 0 {
			out[d.String] = n.Int64
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.CapturedToolTokensByDay: %w", err)
	}
	return out, nil
}

// --- Passive signals, read-only -------------------------------------------------

// PlanPassiveSignals are the passive readings the module merges at read
// time, newest per session within the lookback, with the account
// observations their sessions bind to.
type PlanPassiveSignals struct {
	Limits     []planlimits.LimitRow
	Logs       []planlimits.LogRow
	StatusLine []planlimits.SessionSnapshot
	Accounts   []planlimits.AccountObs
}

// LoadPlanPassiveSignals reads the passive signals since a time. It never
// writes: limit_snapshots keeps its single proxy writer and the codex
// actions their adapter writer.
func (s *Store) LoadPlanPassiveSignals(ctx context.Context, since time.Time) (PlanPassiveSignals, error) {
	var out PlanPassiveSignals
	sessions := map[string]bool{}

	rows, err := s.db.QueryContext(ctx, `
		SELECT l.scope_hash, l.provider, COALESCE(l.session_id, ''), COALESCE(s.tool, ''), l.observed_at,
		       l.window_5h_util, l.window_5h_reset, l.window_7d_util, l.window_7d_reset, COALESCE(l.status, '')
		  FROM limit_snapshots l
		  JOIN (SELECT MAX(id) id FROM limit_snapshots
		         WHERE observed_at >= ? AND (window_5h_util IS NOT NULL OR window_7d_util IS NOT NULL)
		         GROUP BY provider, COALESCE(session_id, '')) m ON m.id = l.id
		  LEFT JOIN sessions s ON s.id = l.session_id`, since.Unix())
	if err != nil {
		return out, fmt.Errorf("store.LoadPlanPassiveSignals: limits: %w", err)
	}
	for rows.Next() {
		var r planlimits.LimitRow
		var at int64
		var w5u, w7u sql.NullFloat64
		var w5r, w7r sql.NullInt64
		if err := rows.Scan(&r.ScopeHash, &r.Provider, &r.SessionID, &r.Tool, &at, &w5u, &w5r, &w7u, &w7r, &r.Status); err != nil {
			rows.Close()
			return out, fmt.Errorf("store.LoadPlanPassiveSignals: limits: %w", err)
		}
		r.ObservedAt = time.Unix(at, 0).UTC()
		r.Window5hUtil, r.Window7dUtil = fptr(w5u), fptr(w7u)
		r.Window5hReset, r.Window7dReset = iptr(w5r), iptr(w7r)
		out.Limits = append(out.Limits, r)
		if r.SessionID != "" {
			sessions[r.SessionID] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, fmt.Errorf("store.LoadPlanPassiveSignals: limits: %w", err)
	}

	tools := make([]string, 0, len(planlimits.PassiveLogTools))
	for t := range planlimits.PassiveLogTools {
		tools = append(tools, t)
	}
	sort.Strings(tools)
	if len(tools) > 0 {
		args := []any{timestamp(since)}
		for _, t := range tools {
			args = append(args, t)
		}
		//nolint:gosec // G202: the IN list is built from placeholders only; values bind via args.
		q := `SELECT a.session_id, a.tool, a.timestamp, a.raw_tool_input FROM actions a
		  JOIN (SELECT MAX(id) id FROM actions
		         WHERE action_type = 'rate_limit' AND timestamp >= ? AND tool IN (` + placeholders(len(tools)) + `)
		           AND raw_tool_input IS NOT NULL AND raw_tool_input <> ''
		         GROUP BY session_id) m ON m.id = a.id`
		rows, err = s.db.QueryContext(ctx, q, args...)
		if err != nil {
			return out, fmt.Errorf("store.LoadPlanPassiveSignals: logs: %w", err)
		}
		for rows.Next() {
			var r planlimits.LogRow
			var ts, raw string
			if err := rows.Scan(&r.SessionID, &r.Tool, &ts, &raw); err != nil {
				rows.Close()
				return out, fmt.Errorf("store.LoadPlanPassiveSignals: logs: %w", err)
			}
			if t, ok := parseDBTime(ts); ok {
				r.ObservedAt = t
			}
			r.Raw = []byte(raw)
			out.Logs = append(out.Logs, r)
			sessions[r.SessionID] = true
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return out, fmt.Errorf("store.LoadPlanPassiveSignals: logs: %w", err)
		}
	}

	rows, err = s.db.QueryContext(ctx, `
		SELECT p.body, COALESCE(p.session_id, '') FROM plan_snapshots p
		  JOIN (SELECT MAX(id) id FROM plan_snapshots
		         WHERE account_id IS NULL AND source = ? AND observed_at >= ?
		         GROUP BY COALESCE(session_id, '')) m ON m.id = p.id`,
		planlimits.SourceClaudeStatusLine, since.Unix())
	if err != nil {
		return out, fmt.Errorf("store.LoadPlanPassiveSignals: status line: %w", err)
	}
	for rows.Next() {
		var body, sid string
		if err := rows.Scan(&body, &sid); err != nil {
			rows.Close()
			return out, fmt.Errorf("store.LoadPlanPassiveSignals: status line: %w", err)
		}
		snap, ok := decodePlanSnapshot(body)
		if !ok {
			continue
		}
		out.StatusLine = append(out.StatusLine, planlimits.SessionSnapshot{SessionID: sid, Snapshot: snap})
		if sid != "" {
			sessions[sid] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, fmt.Errorf("store.LoadPlanPassiveSignals: status line: %w", err)
	}

	obs, err := s.planAccountObservations(ctx, sessions)
	if err != nil {
		return out, err
	}
	out.Accounts = obs
	return out, nil
}

// planAccountObservations loads the login observations of the given sessions,
// in chunks.
func (s *Store) planAccountObservations(ctx context.Context, sessions map[string]bool) ([]planlimits.AccountObs, error) {
	ids := make([]string, 0, len(sessions))
	for id := range sessions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var out []planlimits.AccountObs
	const chunk = 200
	for i := 0; i < len(ids); i += chunk {
		part := ids[i:min(i+chunk, len(ids))]
		args := make([]any, len(part))
		for j, id := range part {
			args[j] = id
		}
		//nolint:gosec // G202: the IN list is built from placeholders only; values bind via args.
		rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT session_id, tool, account_key, email FROM tool_account_observations
			WHERE session_id IN (`+placeholders(len(part))+`)`, args...)
		if err != nil {
			return nil, fmt.Errorf("store.planAccountObservations: %w", err)
		}
		for rows.Next() {
			var o planlimits.AccountObs
			if err := rows.Scan(&o.SessionID, &o.Tool, &o.AccountKey, &o.Label); err != nil {
				rows.Close()
				return nil, fmt.Errorf("store.planAccountObservations: %w", err)
			}
			out = append(out, o)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("store.planAccountObservations: %w", err)
		}
	}
	return out, nil
}

// ObservedToolSpendSince returns Observer's own recorded spend (USD) for
// sessions of the given tools since a time, over the same deduplicated
// substrate the guard budget windows use. It feeds the "estimated from your
// usage" figure of a manual plan entry.
func (s *Store) ObservedToolSpendSince(ctx context.Context, tools []string, since time.Time) (float64, error) {
	if len(tools) == 0 {
		return 0, nil
	}
	args := []any{timestamp(since)}
	for _, t := range tools {
		args = append(args, t)
	}
	var total float64
	//nolint:gosec // G202: spendUnionRecordedSQL is closed constant SQL and the IN list is placeholders; values bind via args.
	err := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(u.c), 0) FROM (`+spendUnionRecordedSQL+`) u
		  JOIN sessions s ON s.id = u.sid
		 WHERE u.ts >= ? AND s.tool IN (`+placeholders(len(tools))+`)`, args...).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("store.ObservedToolSpendSince: %w", err)
	}
	return total, nil
}
