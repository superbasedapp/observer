//go:build !sbo_omit_security

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// The security pillar's local finding exceptions (agent migration 183;
// security pillar plan sections 5.12 and 6.3, lane sec-c3). ONE OWNER:
// sec_finding_exceptions is written exclusively here, and a grant or an
// end moves the excepted finding's status in the same transaction, so the
// finding and its exception never disagree. NODE-LOCAL: the table is in
// the privacy sentinel. A feature-owned file: it leaves the binary with
// sbo_omit_security (the table stays, empty).

// Exception end reasons (the CHECK constraint of migration 183).
const (
	SecExceptionExpired     = "expired"
	SecExceptionFileChanged = "file_changed"
	SecExceptionRevoked     = "revoked"
)

// ErrSecExceptionNotFound reports an unknown or already ended exception.
var ErrSecExceptionNotFound = errors.New("store: security exception not found or already ended")

// ErrSecFindingNotOpen reports a grant on a finding that is no longer open.
var ErrSecFindingNotOpen = errors.New("store: security finding is not open")

// SecException is one row of sec_finding_exceptions.
type SecException struct {
	ID              int64     `json:"id"`
	FindingID       string    `json:"finding_id"`
	ProjectRootHash string    `json:"project_root_hash"`
	LocalKey        string    `json:"-"`
	RuleID          string    `json:"rule_id"`
	Reason          string    `json:"reason"`
	Expiry          string    `json:"expiry"`
	ExpiresAt       time.Time `json:"expires_at"`
	FileHash        string    `json:"-"`
	GrantedBy       string    `json:"granted_by"`
	GrantedAt       time.Time `json:"granted_at"`
	EndedAt         time.Time `json:"ended_at"`
	EndReason       string    `json:"end_reason"`
	// RelPath is the excepted finding's path, joined for display.
	RelPath string `json:"rel_path"`
}

// SecExceptionRef is the exception id a finding's exception_id column
// holds.
func SecExceptionRef(id int64) string { return "sx-" + strconv.FormatInt(id, 10) }

// SecFindingByID returns one finding (the columns a grant and the detail
// view need), false when the id is unknown.
func (s *Store) SecFindingByID(ctx context.Context, id string) (secfinding.Finding, bool, error) {
	var x secfinding.Finding
	var cat, sev, conf, scope, base, status, reached string
	err := s.db.QueryRowContext(ctx, `SELECT id, project_root_hash, local_key, rel_path, start_line, end_line, rule_id,
		category, severity, confidence, scope, baseline, status, message, fix_hint, exception_id, reached_remote_at
		FROM sec_findings WHERE id = ?`, id).Scan(&x.ID, &x.Project.RootHash, &x.LocalKey, &x.Location.RelPath,
		&x.Location.StartLine, &x.Location.EndLine, &x.Rule.ID, &cat, &sev, &conf, &scope, &base, &status,
		&x.Message, &x.FixHint, &x.ExceptionID, &reached)
	if errors.Is(err, sql.ErrNoRows) {
		return secfinding.Finding{}, false, nil
	}
	if err != nil {
		return secfinding.Finding{}, false, fmt.Errorf("store.SecFindingByID: %w", err)
	}
	x.Category, x.Severity, x.Confidence = secfinding.Category(cat), secfinding.Severity(sev), secfinding.Confidence(conf)
	x.Scope, x.Baseline, x.Status = secfinding.Scope(scope), secfinding.Baseline(base), secfinding.Status(status)
	x.FixHint = secPushedHint(secReachedNote(reached, cat, conf), x.FixHint)
	return x, true, nil
}

// GrantSecException records an exception for an open finding and moves
// the finding to status, in one transaction. It refuses a finding that is
// no longer open (ErrSecFindingNotOpen), so two grants cannot race.
func (s *Store) GrantSecException(ctx context.Context, e SecException, status secfinding.Status) (int64, error) {
	if e.FindingID == "" || e.Reason == "" || e.Expiry == "" || e.GrantedBy == "" {
		return 0, errors.New("store.GrantSecException: finding, reason, expiry and origin are required")
	}
	if status == policy.FindingStatusOpen || status == "" {
		return 0, errors.New("store.GrantSecException: an exception moves the finding out of open")
	}
	ts := e.GrantedAt.UTC().Format(secTime)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.GrantSecException: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var root, key, rule string
	err = tx.QueryRowContext(ctx, `SELECT project_root_hash, local_key, rule_id FROM sec_findings WHERE id = ? AND status = 'open'`,
		e.FindingID).Scan(&root, &key, &rule)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrSecFindingNotOpen
	}
	if err != nil {
		return 0, fmt.Errorf("store.GrantSecException: %w", err)
	}
	expires := ""
	if !e.ExpiresAt.IsZero() {
		expires = e.ExpiresAt.UTC().Format(secTime)
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO sec_finding_exceptions
		(finding_id, project_root_hash, local_key, rule_id, reason, expiry, expires_at, file_hash, granted_by, granted_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)`, e.FindingID, root, key, rule, e.Reason, e.Expiry, expires, e.FileHash, e.GrantedBy, ts)
	if err != nil {
		return 0, fmt.Errorf("store.GrantSecException: insert: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("store.GrantSecException: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sec_findings SET status = ?, closed_at = ?, exception_id = ? WHERE id = ?`,
		string(status), ts, SecExceptionRef(id), e.FindingID); err != nil {
		return 0, fmt.Errorf("store.GrantSecException: finding: %w", err)
	}
	detail := SecExceptionRef(id) + ":" + e.Reason + ":" + e.Expiry + ":" + e.GrantedBy
	if err := appendSecEvent(ctx, tx, e.FindingID, root, SecEventSuppressed, detail, ts); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.GrantSecException: %w", err)
	}
	return id, nil
}

// EndSecException ends an open exception (expired, file_changed or
// revoked) and reopens its finding when the finding still carries this
// exception, in one transaction, with the lifecycle event: an expiry or a
// file change records exception_expired, a revoke records reopened.
func (s *Store) EndSecException(ctx context.Context, id int64, reason string, now time.Time) error {
	return s.endSecException(ctx, id, reason, now, false)
}

// EndSecExceptionGone ends an open exception whose finding a fresh rescan
// no longer finds (lane sec-gate2, decision log P-025): the finding, when
// it still carries this exception, closes as not_reproduced instead of
// reopening, its sightings are dropped, and a closed event is recorded. A
// later sighting reopens it (UpsertSecFinding).
func (s *Store) EndSecExceptionGone(ctx context.Context, id int64, reason string, now time.Time) error {
	return s.endSecException(ctx, id, reason, now, true)
}

func (s *Store) endSecException(ctx context.Context, id int64, reason string, now time.Time, gone bool) error {
	switch reason {
	case SecExceptionExpired, SecExceptionFileChanged, SecExceptionRevoked:
	default:
		return fmt.Errorf("store.EndSecException: unknown end reason %q", reason)
	}
	ts := now.UTC().Format(secTime)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.EndSecException: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var findingID, root string
	err = tx.QueryRowContext(ctx, `SELECT finding_id, project_root_hash FROM sec_finding_exceptions WHERE id = ? AND ended_at = ''`, id).
		Scan(&findingID, &root)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrSecExceptionNotFound
	}
	if err != nil {
		return fmt.Errorf("store.EndSecException: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sec_finding_exceptions SET ended_at = ?, end_reason = ? WHERE id = ?`, ts, reason, id); err != nil {
		return fmt.Errorf("store.EndSecException: %w", err)
	}
	if gone {
		// A secret no file holds any more is still in an unpushed commit,
		// or already reached a remote: the finding reopens instead of
		// closing (lanes sec-gate3 and sec-gate4).
		held, err := secFindingKept(ctx, tx, findingID)
		if err != nil {
			return err
		}
		gone = !held
	}
	status, closedAt := "open", ""
	if gone {
		status, closedAt = string(policy.FindingStatusNotReproduced), ts
	}
	res, err := tx.ExecContext(ctx, `UPDATE sec_findings SET status = ?, closed_at = ?, exception_id = ''
		WHERE id = ? AND exception_id = ?`, status, closedAt, findingID, SecExceptionRef(id))
	if err != nil {
		return fmt.Errorf("store.EndSecException: finding: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		kind := SecEventExceptionExpired
		switch {
		case gone:
			kind = SecEventClosed
			if _, err := tx.ExecContext(ctx, `DELETE FROM sec_finding_sightings WHERE finding_id = ?`, findingID); err != nil {
				return fmt.Errorf("store.EndSecException: sightings: %w", err)
			}
		case reason == SecExceptionRevoked:
			kind = SecEventReopened
		}
		if err := appendSecEvent(ctx, tx, findingID, root, kind, SecExceptionRef(id)+":"+reason, ts); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.EndSecException: %w", err)
	}
	return nil
}

// secExpiryUntilChange is the expiry id of an "until the file changes"
// exception (secexcept.ExpiryUntilChange; the store does not import the
// pure package).
const secExpiryUntilChange = "until_change"

// SecExceptionFilter selects exceptions for ListSecExceptions.
type SecExceptionFilter struct {
	ProjectRootHash string
	// OpenOnly lists only the exceptions still applying.
	OpenOnly bool
	// SoonestFirst orders by expiry, the soonest first (one with no expiry
	// at all last), instead of newest first: the sweep reads the timed
	// exceptions that end next (lane sec-gate2). An until-change
	// exception's expiry is its far ceiling, so the sweep reads those on a
	// page of their own (UntilChange, lane sec-gate3).
	SoonestFirst bool
	// Timed lists only the exceptions with a fixed lifetime; UntilChange
	// only the "until the file changes" ones, whose expiry is only a far
	// ceiling (lane sec-gate3 milestone 2d:
	// the sweep reads the two on separate budgets, so a thousand timed
	// exceptions can never keep an until-change one from its file check).
	Timed       bool
	UntilChange bool
	// AfterID lists only exceptions with a greater id; OldestFirst orders
	// by id, the oldest first (the sweep's rotating page over the
	// until-change ones).
	AfterID     int64
	OldestFirst bool
	Limit       int
}

// ListSecExceptions returns exceptions newest first (at most Limit,
// default 200, at most 1000), with the excepted finding's path.
func (s *Store) ListSecExceptions(ctx context.Context, f SecExceptionFilter) ([]SecException, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	limit = min(limit, 1000)
	var where []string
	var args []any
	if f.ProjectRootHash != "" {
		where, args = append(where, "e.project_root_hash = ?"), append(args, f.ProjectRootHash)
	}
	if f.OpenOnly {
		where = append(where, "e.ended_at = ''")
	}
	if f.Timed {
		where, args = append(where, "e.expiry <> ?"), append(args, secExpiryUntilChange)
	}
	if f.UntilChange {
		where, args = append(where, "e.expiry = ?"), append(args, secExpiryUntilChange)
	}
	if f.AfterID > 0 {
		where, args = append(where, "e.id > ?"), append(args, f.AfterID)
	}
	q := `SELECT e.id, e.finding_id, e.project_root_hash, e.local_key, e.rule_id, e.reason, e.expiry, e.expires_at,
		e.file_hash, e.granted_by, e.granted_at, e.ended_at, e.end_reason, COALESCE(f.rel_path, '')
		FROM sec_finding_exceptions e LEFT JOIN sec_findings f ON f.id = e.finding_id`
	if len(where) > 0 {
		//nolint:gosec // G202: the clauses are fixed literals above; every value is a bound parameter.
		q += " WHERE " + strings.Join(where, " AND ")
	}
	switch {
	case f.SoonestFirst:
		q += " ORDER BY CASE WHEN e.expires_at = '' THEN 1 ELSE 0 END, e.expires_at, e.id LIMIT ?"
	case f.OldestFirst:
		q += " ORDER BY e.id LIMIT ?"
	default:
		q += " ORDER BY e.id DESC LIMIT ?"
	}
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store.ListSecExceptions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []SecException
	for rows.Next() {
		var x SecException
		var expires, granted, ended string
		if err := rows.Scan(&x.ID, &x.FindingID, &x.ProjectRootHash, &x.LocalKey, &x.RuleID, &x.Reason, &x.Expiry, &expires,
			&x.FileHash, &x.GrantedBy, &granted, &ended, &x.EndReason, &x.RelPath); err != nil {
			return nil, fmt.Errorf("store.ListSecExceptions: %w", err)
		}
		x.ExpiresAt, _ = time.Parse(secTime, expires)
		x.GrantedAt, _ = time.Parse(secTime, granted)
		x.EndedAt, _ = time.Parse(secTime, ended)
		out = append(out, x)
	}
	return out, rows.Err()
}

// SecFindingSightings returns the files a finding is sighted in (its own
// location when it has no sighting row).
func (s *Store) SecFindingSightings(ctx context.Context, findingID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT rel_path FROM sec_finding_sightings WHERE finding_id = ?
		UNION SELECT rel_path FROM sec_findings WHERE id = ? AND rel_path <> ''
			AND NOT EXISTS (SELECT 1 FROM sec_finding_sightings WHERE finding_id = ?)
		ORDER BY 1`, findingID, findingID, findingID)
	if err != nil {
		return nil, fmt.Errorf("store.SecFindingSightings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, fmt.Errorf("store.SecFindingSightings: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PruneSecExceptions deletes ended exceptions that ended before cutoff and
// every exception whose finding the retention pass already deleted
// ([security.retention].days). An exception still applying to a finding
// that exists is never deleted.
func (s *Store) PruneSecExceptions(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sec_finding_exceptions
		WHERE (ended_at <> '' AND ended_at < ?) OR finding_id NOT IN (SELECT id FROM sec_findings)`, cutoff.UTC().Format(secTime))
	if err != nil {
		return 0, fmt.Errorf("store.PruneSecExceptions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// SecSeenFinding is one newly seen finding for the desktop notification.
type SecSeenFinding struct {
	EventID         int64
	FindingID       string
	ProjectRootHash string
	RuleID          string
	RelPath         string
}

// SecMaxFindingEventID returns the newest lifecycle event id (0 when none),
// the notification's starting watermark.
func (s *Store) SecMaxFindingEventID(ctx context.Context) (int64, error) {
	var id sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(id) FROM sec_finding_events`).Scan(&id); err != nil {
		return 0, fmt.Errorf("store.SecMaxFindingEventID: %w", err)
	}
	return id.Int64, nil
}

// SecSeenAfter returns findings first seen (a seen event) after the event
// id, at the given severity and still open, oldest first, at most limit
// (lane sec-c3: the critical-finding desktop notification).
func (s *Store) SecSeenAfter(ctx context.Context, afterEventID int64, severity secfinding.Severity, limit int) ([]SecSeenFinding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT e.id, f.id, f.project_root_hash, f.rule_id, f.rel_path
		FROM sec_finding_events e JOIN sec_findings f ON f.id = e.finding_id
		WHERE e.id > ? AND e.kind = 'seen' AND f.severity = ? AND f.status = 'open'
		ORDER BY e.id LIMIT ?`, afterEventID, string(severity), limit)
	if err != nil {
		return nil, fmt.Errorf("store.SecSeenAfter: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []SecSeenFinding
	for rows.Next() {
		var x SecSeenFinding
		if err := rows.Scan(&x.EventID, &x.FindingID, &x.ProjectRootHash, &x.RuleID, &x.RelPath); err != nil {
			return nil, fmt.Errorf("store.SecSeenAfter: %w", err)
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
