package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// SANDBOX EGRESS REFUSAL AUDIT (OpenShell build plan 05 section 3.1, lane
// N1; agent migration 230). This file is the ONE owner of the node-local
// sandbox_egress_refusals table: InsertSandboxEgressRefusal is its only
// writer (called by the daemon's refusal receiver, which a host helper
// reaches over the capture relay link; a helper never opens the database),
// PruneSandboxEgressRefusals its retention delete, and the two list reads
// the only reads. The table name never enters orgpush.go (decision D6;
// privacy sentinel, tests/invariant/privacy_test.go). It also owns the
// sandbox_egress_refusal_drops table beside it (agent migration 231, lane
// OC, audit finding O3-W2): AddSandboxEgressRefusalDrops is its only writer
// (the same receiver), SandboxEgressRefusalDrops its only read, and the
// same retention delete prunes it.

// sandboxEgressTimeLayout is fixed width, so refused_at compares correctly
// as a string.
const sandboxEgressTimeLayout = "2006-01-02T15:04:05.000000000Z"

// SandboxEgressRefusalRetention is how long a refusal row is kept.
const SandboxEgressRefusalRetention = 30 * 24 * time.Hour

// SandboxEgressRefusalMaxPerRun is the most rows one run keeps (tracker
// F-009, audit finding N1-A4). The flood bound passes at most 30 rows per
// run a minute, so a long hostile run could otherwise keep about 1.3
// million rows over the retention window; past this bound the run's
// oldest rows are removed as each new one is written, and the removals are
// counted beside the run (sandbox_egress_refusal_drops.evicted, migration
// 233), so the run reads as incomplete, never as whole. At the flood
// bound's rate a run reaches it after about five and a half hours.
const SandboxEgressRefusalMaxPerRun = 10000

// sandboxEgressRefusalMaxPerRun is the bound in force (a var for tests).
var sandboxEgressRefusalMaxPerRun = SandboxEgressRefusalMaxPerRun

// Page bounds of the list reads.
const (
	SandboxEgressRefusalDefaultPage = 100
	SandboxEgressRefusalMaxPage     = 500
)

// maxSandboxEgressField caps a stored text field (a host name is at most
// 253 bytes; the rest are short closed values).
const maxSandboxEgressField = 255

// SandboxEgressRefusal is one stored refusal. Rule is the closed
// internal/sandboxnet.RefusalRule value and Key the config or pin key that
// decided. Backend and Tier left empty on insert are filled from the
// run's stored terminal_run row (stack, egress_tier) when it has one.
type SandboxEgressRefusal struct {
	ID          int64     `json:"id"`
	RunID       string    `json:"run_id"`
	ProjectRoot string    `json:"project_root"`
	Backend     string    `json:"backend"`
	Tier        string    `json:"tier"`
	Host        string    `json:"host"`
	Port        int       `json:"port"`
	Rule        string    `json:"rule"`
	Key         string    `json:"key"`
	At          time.Time `json:"at"`
}

// capSandboxEgressField bounds a stored text field to maxSandboxEgressField bytes.
func capSandboxEgressField(s string) string {
	if len(s) <= maxSandboxEgressField {
		return s
	}
	return strings.ToValidUTF8(s[:maxSandboxEgressField], "")
}

// InsertSandboxEgressRefusal writes one refusal. A second refusal of the
// same host for the same run in the same minute is ignored (the flood
// bound): inserted reports whether a row was written.
func (s *Store) InsertSandboxEgressRefusal(ctx context.Context, r SandboxEgressRefusal) (bool, error) {
	if r.RunID == "" || r.Host == "" || r.Rule == "" {
		return false, fmt.Errorf("store.InsertSandboxEgressRefusal: run id, host and rule are required")
	}
	at := r.At.UTC()
	if at.IsZero() {
		at = time.Now().UTC()
	}
	runID := capSandboxEgressField(r.RunID)
	// The insert and the per-run bound run in one transaction (audit
	// finding FU5-A7), so the table never holds a run over the bound.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("store.InsertSandboxEgressRefusal: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO sandbox_egress_refusals
			(run_id, project_root, backend, tier, host, port, rule, rule_key, minute_bucket, refused_at)
		VALUES (?, ?,
			COALESCE(NULLIF(?, ''), (SELECT stack FROM terminal_run WHERE run_id = ?), ''),
			COALESCE(NULLIF(?, ''), (SELECT egress_tier FROM terminal_run WHERE run_id = ?), ''),
			?, ?, ?, ?, ?, ?)`,
		runID, r.ProjectRoot,
		capSandboxEgressField(r.Backend), runID,
		capSandboxEgressField(r.Tier), runID,
		capSandboxEgressField(r.Host), r.Port, capSandboxEgressField(r.Rule), capSandboxEgressField(r.Key),
		sandboxvocab.EgressRefusalMinute(at), at.Format(sandboxEgressTimeLayout))
	if err != nil {
		return false, fmt.Errorf("store.InsertSandboxEgressRefusal: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return false, nil
	}
	if err := evictSandboxEgressRefusals(ctx, tx, runID, at); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("store.InsertSandboxEgressRefusal: %w", err)
	}
	return true, nil
}

// evictSandboxEgressRefusals keeps runID under the per-run bound inside
// the insert's transaction: past it the oldest rows go (by refusal time,
// then id), and how many is added to the run's evicted count.
func evictSandboxEgressRefusals(ctx context.Context, tx *sql.Tx, runID string, at time.Time) error {
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sandbox_egress_refusals WHERE run_id = ?`, runID).Scan(&count); err != nil {
		return fmt.Errorf("store.InsertSandboxEgressRefusal: evict: %w", err)
	}
	over := count - sandboxEgressRefusalMaxPerRun
	if over <= 0 {
		return nil
	}
	res, err := tx.ExecContext(ctx, `
		DELETE FROM sandbox_egress_refusals WHERE id IN (
			SELECT id FROM sandbox_egress_refusals WHERE run_id = ? ORDER BY refused_at, id LIMIT ?)`, runID, over)
	if err != nil {
		return fmt.Errorf("store.InsertSandboxEgressRefusal: evict: %w", err)
	}
	gone, _ := res.RowsAffected()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO sandbox_egress_refusal_drops (run_id, evicted, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(run_id) DO UPDATE SET evicted = evicted + excluded.evicted, updated_at = excluded.updated_at`,
		runID, gone, at.Format(sandboxEgressTimeLayout)); err != nil {
		return fmt.Errorf("store.InsertSandboxEgressRefusal: evict: %w", err)
	}
	return nil
}

// SandboxEgressRefusalQuery selects a page of refusals, newest written
// first.
// RunID and ProjectRoot filter when set (both: both must match). Before,
// when non-zero, returns only rows with a smaller id (the next page).
// Limit zero is SandboxEgressRefusalDefaultPage; it is capped at
// SandboxEgressRefusalMaxPage.
type SandboxEgressRefusalQuery struct {
	RunID       string
	ProjectRoot string
	Before      int64
	Limit       int
}

// ListSandboxEgressRefusalsByRun returns a page of runID's refusals, newest
// first.
func (s *Store) ListSandboxEgressRefusalsByRun(ctx context.Context, runID string, before int64, limit int) ([]SandboxEgressRefusal, error) {
	return s.ListSandboxEgressRefusals(ctx, SandboxEgressRefusalQuery{RunID: runID, Before: before, Limit: limit})
}

// ListSandboxEgressRefusalsByProject returns a page of the refusals of runs
// attributed to projectRoot, newest first.
func (s *Store) ListSandboxEgressRefusalsByProject(ctx context.Context, projectRoot string, before int64, limit int) ([]SandboxEgressRefusal, error) {
	return s.ListSandboxEgressRefusals(ctx, SandboxEgressRefusalQuery{ProjectRoot: projectRoot, Before: before, Limit: limit})
}

// ListSandboxEgressRefusals returns the page q selects, newest first.
func (s *Store) ListSandboxEgressRefusals(ctx context.Context, q SandboxEgressRefusalQuery) ([]SandboxEgressRefusal, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = SandboxEgressRefusalDefaultPage
	}
	limit = min(limit, SandboxEgressRefusalMaxPage)
	var where []string
	var args []any
	if q.RunID != "" {
		where = append(where, "run_id = ?")
		args = append(args, q.RunID)
	}
	if q.ProjectRoot != "" {
		where = append(where, "project_root = ?")
		args = append(args, q.ProjectRoot)
	}
	if q.Before > 0 {
		where = append(where, "id < ?")
		args = append(args, q.Before)
	}
	query := `SELECT id, run_id, project_root, backend, tier, host, port, rule, rule_key, refused_at FROM sandbox_egress_refusals`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ") //nolint:gosec // G202: the joined fragments are fixed SQL with ? placeholders; values bind as args
	}
	// Newest written first: the id is the write order, and the before
	// cursor is an id, so ordering on anything else could skip or repeat
	// a row across pages.
	query += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store.ListSandboxEgressRefusals: %w", err)
	}
	defer rows.Close()
	out := []SandboxEgressRefusal{}
	for rows.Next() {
		var r SandboxEgressRefusal
		var at string
		if err := rows.Scan(&r.ID, &r.RunID, &r.ProjectRoot, &r.Backend, &r.Tier, &r.Host, &r.Port, &r.Rule, &r.Key, &at); err != nil {
			return nil, fmt.Errorf("store.ListSandboxEgressRefusals: scan: %w", err)
		}
		r.At, _ = time.Parse(sandboxEgressTimeLayout, at)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ListSandboxEgressRefusals: %w", err)
	}
	return out, nil
}

// PruneSandboxEgressRefusals deletes the refusals older than cutoff and
// returns how many it deleted; the dropped counts not added to since
// cutoff go with them.
func (s *Store) PruneSandboxEgressRefusals(ctx context.Context, cutoff time.Time) (int64, error) {
	c := cutoff.UTC().Format(sandboxEgressTimeLayout)
	res, err := s.db.ExecContext(ctx, `DELETE FROM sandbox_egress_refusals WHERE refused_at < ?`, c)
	if err != nil {
		return 0, fmt.Errorf("store.PruneSandboxEgressRefusals: %w", err)
	}
	n, _ := res.RowsAffected()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sandbox_egress_refusal_drops WHERE updated_at < ?`, c); err != nil {
		return n, fmt.Errorf("store.PruneSandboxEgressRefusals: drops: %w", err)
	}
	return n, nil
}

// AddSandboxEgressRefusalDrops adds to runID's dropped-refusal counts:
// dropped refusals of this run, and uncertain ones that may be this run's
// (refusals a feed or the receiver dropped before they could be written;
// audit findings O3-W2 and OC-A1). At least one count must be positive.
func (s *Store) AddSandboxEgressRefusalDrops(ctx context.Context, runID string, dropped, uncertain int, at time.Time) error {
	if runID == "" || dropped < 0 || uncertain < 0 || dropped+uncertain == 0 {
		return fmt.Errorf("store.AddSandboxEgressRefusalDrops: a run id and a positive count are required")
	}
	if at.IsZero() {
		at = time.Now()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sandbox_egress_refusal_drops (run_id, dropped, uncertain, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(run_id) DO UPDATE SET dropped = dropped + excluded.dropped, uncertain = uncertain + excluded.uncertain, updated_at = excluded.updated_at`,
		capSandboxEgressField(runID), dropped, uncertain, at.UTC().Format(sandboxEgressTimeLayout))
	if err != nil {
		return fmt.Errorf("store.AddSandboxEgressRefusalDrops: %w", err)
	}
	return nil
}

// AddSandboxEgressRefusalLinkLoss adds what runID's host helper could not
// send to the daemon (tracker F-012, audit findings N4-A4 and FU5-A4;
// migration 233): refusals it could not send, the link down or the daemon
// busy (added to both dropped and link_lost, since every lost refusal is a
// dropped one), and new requests it refused while the link was down under
// the org's require_refusal_audit floor (egress_closed; not refusals, so
// not in dropped). At least one count
// must be positive.
func (s *Store) AddSandboxEgressRefusalLinkLoss(ctx context.Context, runID string, lost, closed int, at time.Time) error {
	if runID == "" || lost < 0 || closed < 0 || lost+closed == 0 {
		return fmt.Errorf("store.AddSandboxEgressRefusalLinkLoss: a run id and a positive count are required")
	}
	if at.IsZero() {
		at = time.Now()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sandbox_egress_refusal_drops (run_id, dropped, uncertain, link_lost, egress_closed, updated_at) VALUES (?, ?, 0, ?, ?, ?)
		ON CONFLICT(run_id) DO UPDATE SET dropped = dropped + excluded.dropped, link_lost = link_lost + excluded.link_lost,
			egress_closed = egress_closed + excluded.egress_closed, updated_at = excluded.updated_at`,
		capSandboxEgressField(runID), lost, lost, closed, at.UTC().Format(sandboxEgressTimeLayout))
	if err != nil {
		return fmt.Errorf("store.AddSandboxEgressRefusalLinkLoss: %w", err)
	}
	return nil
}

// SandboxEgressRefusalDrop is one run's dropped-refusal counts.
type SandboxEgressRefusalDrop struct {
	// Dropped is the refusals of the run dropped before they were written.
	Dropped int
	// Uncertain is the refusals that may be the run's, dropped while its
	// box id was not recorded yet and the claimed box was not remembered.
	Uncertain int
	// LinkLost is the part of Dropped the run's host helper could not send
	// to the daemon (the link down, or the daemon busy; migration 233).
	LinkLost int
	// EgressClosed is the new requests refused while the run's link was
	// down under require_refusal_audit (migration 233).
	EgressClosed int
	// Evicted is the run's oldest rows removed to keep it under
	// SandboxEgressRefusalMaxPerRun (migration 233).
	Evicted int
}

// SandboxEgressRefusalDrops returns the dropped-refusal counts of runIDs
// (runs with none are absent; at most SandboxEgressRefusalMaxPage ids are
// read).
func (s *Store) SandboxEgressRefusalDrops(ctx context.Context, runIDs []string) (map[string]SandboxEgressRefusalDrop, error) {
	out := map[string]SandboxEgressRefusalDrop{}
	seen := map[string]bool{}
	var args []any
	for _, id := range runIDs {
		if id == "" || seen[id] || len(args) >= SandboxEgressRefusalMaxPage {
			continue
		}
		seen[id] = true
		args = append(args, id)
	}
	if len(args) == 0 {
		return out, nil
	}
	q := `SELECT run_id, dropped, uncertain, link_lost, egress_closed, evicted FROM sandbox_egress_refusal_drops WHERE run_id IN (?` + strings.Repeat(",?", len(args)-1) + `)` //nolint:gosec // G202: only ? placeholders are joined; values bind as args
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store.SandboxEgressRefusalDrops: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var d SandboxEgressRefusalDrop
		if err := rows.Scan(&id, &d.Dropped, &d.Uncertain, &d.LinkLost, &d.EgressClosed, &d.Evicted); err != nil {
			return nil, fmt.Errorf("store.SandboxEgressRefusalDrops: scan: %w", err)
		}
		out[id] = d
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SandboxEgressRefusalDrops: %w", err)
	}
	return out, nil
}
