package spendverdict

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// RuleVersion is the version of sessionmsg's dedup decisions the stored
// verdicts are computed with. Bump it with any change to
// sessionmsg.DeriveVerdicts' output: the next Refresh re-queues every
// candidate session once (the org's rollup.spendDedupRuleVersion is the same
// contract on the other engine).
//
// Version 1: sessionmsg.Derive as of lane R2-ONERULE - the per-turn pairing
// (ids, one-to-one closest-timestamp shape twins with the transcript's
// clamped visible output, output-only shadow rows) and the
// session-cumulative reconciliation.
const RuleVersion = 1

// Options bounds one Refresh.
type Options struct {
	// MaxDuration stops a Refresh after this long (checked between
	// transactions); the sessions left queued are picked up by the next
	// Refresh. Zero means unbounded: every queued session is re-derived.
	MaxDuration time.Duration
}

// batchSessions / batchDuration bound one write transaction, so a large
// queue (the one-time backfill after an upgrade) never holds SQLite's write
// lock for long while still amortizing a commit over several sessions.
const (
	batchSessions = 64
	batchDuration = 150 * time.Millisecond
)

// refreshLocks serializes Refresh per database within one process: readers
// that fire together (a dashboard page's panels) share one pass instead of
// racing to re-derive the same queued sessions.
var refreshLocks sync.Map // *sql.DB -> *sync.Mutex

// Refresh re-derives every session queued in spend_verdict_dirty (and, once
// per RuleVersion, queues every candidate session first) and returns how
// many sessions it re-derived. A windowed spend reader calls it before
// reading; the daemon calls it on a ticker. It is safe to call concurrently
// from any process: each session is re-derived inside one write transaction
// that re-checks and clears its queue entry.
//
// A database without the verdict tables (an unmigrated test schema) is a
// no-op, not an error.
func Refresh(ctx context.Context, db *sql.DB, opts Options) (int, error) {
	if db == nil {
		return 0, nil
	}
	muAny, _ := refreshLocks.LoadOrStore(db, &sync.Mutex{})
	mu := muAny.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	var deadline time.Time
	if opts.MaxDuration > 0 {
		deadline = time.Now().Add(opts.MaxDuration)
	}
	if err := ensureRuleVersion(ctx, db); err != nil {
		if isMissingTable(err) {
			return 0, nil
		}
		return 0, err
	}
	done := 0
	for {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return done, nil
		}
		ids, err := queued(ctx, db, batchSessions)
		if err != nil {
			return done, err
		}
		if len(ids) == 0 {
			return done, nil
		}
		n, err := rederiveBatch(ctx, db, ids)
		done += n
		if err != nil {
			return done, err
		}
	}
}

// queued returns up to limit queued session ids.
func queued(ctx context.Context, db *sql.DB, limit int) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT session_id FROM spend_verdict_dirty LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("spendverdict.Refresh: queue: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("spendverdict.Refresh: queue: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// rederiveBatch re-derives the queued sessions in ids inside ONE write
// transaction (stopping early after batchDuration), and returns how many it
// processed. A session another process already cleared is skipped.
func rederiveBatch(ctx context.Context, db *sql.DB, ids []string) (int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("spendverdict.Refresh: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	start := time.Now()
	done := 0
	for _, id := range ids {
		if done > 0 && time.Since(start) > batchDuration {
			break
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM spend_verdict_dirty WHERE session_id = ?`, id)
		if err != nil {
			return 0, fmt.Errorf("spendverdict.Refresh: dequeue: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			continue // another writer re-derived it after we listed it
		}
		if err := rederive(ctx, tx, id); err != nil {
			return 0, fmt.Errorf("spendverdict.Refresh: %s: %w", id, err)
		}
		done++
	}
	if done > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE spend_verdict_state SET rev = rev + 1 WHERE k = 1`); err != nil {
			return 0, fmt.Errorf("spendverdict.Refresh: rev: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("spendverdict.Refresh: commit: %w", err)
	}
	return done, nil
}

// rederive replaces one session's stored verdicts with Derive's current
// decisions over its current rows. q is the refresh transaction.
func rederive(ctx context.Context, q Querier, sessionID string) error {
	if _, err := q.ExecContext(ctx, `DELETE FROM spend_verdict_token WHERE session_id = ?`, sessionID); err != nil {
		return fmt.Errorf("clear token verdicts: %w", err)
	}
	if _, err := q.ExecContext(ctx, `DELETE FROM spend_verdict_proxy WHERE session_id = ?`, sessionID); err != nil {
		return fmt.Errorf("clear proxy verdicts: %w", err)
	}
	// A session no proxy observed has nothing to dedup unless its tool
	// writes output-only shadow rows or a session-cumulative row: skip the
	// row load for the common transcript-only session.
	var tool string
	if err := q.QueryRowContext(ctx, `SELECT COALESCE(tool,'') FROM sessions WHERE id = ?`, sessionID).Scan(&tool); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("session: %w", err)
	}
	if caps := CapsFor(tool); !caps.ShadowCapable && !caps.SessionCumulative {
		var one int
		err := q.QueryRowContext(ctx, `SELECT 1 FROM api_turns WHERE session_id = ? LIMIT 1`, sessionID).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("proxy probe: %w", err)
		}
	}
	rows, err := LoadSession(ctx, q, sessionID)
	if err != nil {
		return err
	}
	v := rows.Verdicts()
	for i, counted := range v.TokenCounted {
		if counted {
			continue
		}
		// ON CONFLICT re-stamps a row another session still holds a verdict
		// for (a row the node moved between sessions): the session that
		// owns the row now always ends up holding its verdict, whichever of
		// the two is re-derived first.
		if _, err := q.ExecContext(ctx,
			`INSERT INTO spend_verdict_token (token_usage_id, session_id, shadow) VALUES (?, ?, ?)
			 ON CONFLICT (token_usage_id) DO UPDATE SET session_id = excluded.session_id, shadow = excluded.shadow`,
			rows.TokenIDs[i], sessionID, boolInt(v.TokenShadow[i])); err != nil {
			return fmt.Errorf("store token verdict: %w", err)
		}
	}
	for i, p := range rows.Proxies {
		lift := v.ProxyInheritedFast[i] && !p.Fast
		if !v.ProxyAdjusted(i, p.Output) && !lift {
			continue
		}
		if _, err := q.ExecContext(ctx,
			`INSERT INTO spend_verdict_proxy (api_turn_id, session_id, counted, output_tokens, reasoning_tokens, inherited_fast)
			 VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT (api_turn_id) DO UPDATE SET session_id = excluded.session_id,
			     counted = excluded.counted, output_tokens = excluded.output_tokens,
			     reasoning_tokens = excluded.reasoning_tokens, inherited_fast = excluded.inherited_fast`,
			rows.ProxyIDs[i], sessionID, boolInt(v.ProxyCounted[i]), v.ProxyOutput[i], v.ProxyReasoning[i], boolInt(lift)); err != nil {
			return fmt.Errorf("store proxy verdict: %w", err)
		}
	}
	return nil
}

// ensureRuleVersion queues every session that can carry a verdict when the
// stored verdicts predate RuleVersion (including a fresh migration), then
// records the version. The queue is then drained by the ordinary Refresh
// loop, so the one-time backfill needs no second code path.
func ensureRuleVersion(ctx context.Context, db *sql.DB) error {
	var version int
	if err := db.QueryRowContext(ctx, `SELECT rule_version FROM spend_verdict_state WHERE k = 1`).Scan(&version); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			version = 0
		} else {
			return fmt.Errorf("spendverdict.Refresh: state: %w", err)
		}
	}
	if version >= RuleVersion {
		return nil
	}
	var capable []any
	for _, tool := range integration.Tools() {
		if c := CapsFor(tool); c.ShadowCapable || c.SessionCumulative {
			capable = append(capable, tool)
		}
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("spendverdict.Refresh: begin backfill: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	q := `INSERT OR IGNORE INTO spend_verdict_dirty (session_id)
	      SELECT DISTINCT session_id FROM api_turns WHERE COALESCE(session_id, '') <> ''`
	if len(capable) > 0 {
		//nolint:gosec // G202: only a ?-placeholder list is interpolated; tool ids bind via args.
		q += ` UNION SELECT id FROM sessions WHERE tool IN (` + strings.TrimSuffix(strings.Repeat("?,", len(capable)), ",") + `)`
	}
	if _, err := tx.ExecContext(ctx, q, capable...); err != nil {
		return fmt.Errorf("spendverdict.Refresh: queue backfill: %w", err)
	}
	// Verdicts of a session that no longer qualifies are stale too: queue
	// every session that holds one.
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO spend_verdict_dirty (session_id)
		SELECT session_id FROM spend_verdict_token UNION SELECT session_id FROM spend_verdict_proxy`); err != nil {
		return fmt.Errorf("spendverdict.Refresh: queue stale: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO spend_verdict_state (k, rule_version, rev) VALUES (1, ?, 0)
		ON CONFLICT (k) DO UPDATE SET rule_version = excluded.rule_version`, RuleVersion); err != nil {
		return fmt.Errorf("spendverdict.Refresh: record version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("spendverdict.Refresh: commit backfill: %w", err)
	}
	return nil
}

// Pending reports how many sessions are queued for re-derivation (for
// `observer doctor`-style diagnostics and tests).
func Pending(ctx context.Context, db *sql.DB) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM spend_verdict_dirty`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("spendverdict.Pending: %w", err)
	}
	return n, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// isMissingTable reports whether err is SQLite's "no such table" (the
// verdict tables are absent: a database migrated by an older binary).
func isMissingTable(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no such table")
}
