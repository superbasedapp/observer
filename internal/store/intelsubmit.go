package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// intelsubmit.go is the ONE store seam for org_intel_outbox (agent migration
// 154; Cloud Intelligence parity phase 2, the B1 rail): the node's org-plane
// submissions of node-built evidence. Node-local (privacy sentinel); the
// evidence leaves only through POST /api/agent/intel/evidence.

// Org-plane outbox states.
const (
	OrgIntelOutboxPending         = "pending"
	OrgIntelOutboxFailedRetryable = "failed_retryable"
	OrgIntelOutboxSubmitted       = "submitted"
	OrgIntelOutboxDuplicate       = "duplicate"
	OrgIntelOutboxAlreadyEnriched = "already_enriched"
	OrgIntelOutboxRefused         = "refused"
)

// Org-plane submission triggers.
const (
	OrgIntelTriggerBackground = "background"
	OrgIntelTriggerDeveloper  = "developer"
)

// orgIntelOutboxTerminal reports whether a state is final (its bytes are
// cleared).
func orgIntelOutboxTerminal(state string) bool {
	switch state {
	case OrgIntelOutboxSubmitted, OrgIntelOutboxDuplicate, OrgIntelOutboxAlreadyEnriched, OrgIntelOutboxRefused:
		return true
	}
	return false
}

// OrgIntelSubmission is one org_intel_outbox row.
type OrgIntelSubmission struct {
	ID             int64     `json:"id"`
	OrgID          string    `json:"org_id"`
	SessionID      string    `json:"session_id"`
	Purpose        string    `json:"purpose"`
	EvidenceLevel  string    `json:"evidence_level"`
	Trigger        string    `json:"trigger"`
	EvidenceDigest string    `json:"evidence_digest"`
	UploadDigest   string    `json:"upload_digest"`
	Envelope       []byte    `json:"-"`
	Bytes          int       `json:"bytes"`
	State          string    `json:"state"`
	Reason         string    `json:"reason,omitempty"`
	JobID          int64     `json:"job_id,omitempty"`
	Attempts       int       `json:"attempts"`
	NextAt         time.Time `json:"next_at,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

const orgIntelOutboxCols = `id, org_id, session_id, purpose, evidence_level, trigger_kind, evidence_digest, upload_digest,
       envelope, bytes, state, reason, job_id, attempts, next_at, created_at, updated_at`

func scanOrgIntelSubmission(scan func(...any) error) (OrgIntelSubmission, error) {
	var (
		r                       OrgIntelSubmission
		env, next, created, upd string
	)
	if err := scan(&r.ID, &r.OrgID, &r.SessionID, &r.Purpose, &r.EvidenceLevel, &r.Trigger, &r.EvidenceDigest, &r.UploadDigest,
		&env, &r.Bytes, &r.State, &r.Reason, &r.JobID, &r.Attempts, &next, &created, &upd); err != nil {
		return OrgIntelSubmission{}, err
	}
	if env != "" {
		r.Envelope = []byte(env)
	}
	r.NextAt, r.CreatedAt, r.UpdatedAt = cloudParseTime(next), cloudParseTime(created), cloudParseTime(upd)
	return r, nil
}

// ErrOrgIntelSessionNotThisOrg refuses an org-plane submission for a session
// whose data belongs to another organization, or to no organization (agent
// migration 250, operator ruling D-43).
var ErrOrgIntelSessionNotThisOrg = errors.New("store.EnqueueOrgIntelSubmission: the session was not captured under this organization")

// EnqueueOrgIntelSubmission adds a submission (state pending). The same bytes
// for the same (org, session, purpose) are not queued twice: the existing row
// is returned with inserted=false. A session captured under another
// organization (or none) is refused with ErrOrgIntelSessionNotThisOrg, so
// neither the background sweep nor a developer's Enrich now can send it.
func (s *Store) EnqueueOrgIntelSubmission(ctx context.Context, in OrgIntelSubmission, now time.Time) (OrgIntelSubmission, bool, error) {
	if in.OrgID == "" || in.SessionID == "" || in.Purpose == "" || in.EvidenceLevel == "" || len(in.Envelope) == 0 || in.UploadDigest == "" {
		return OrgIntelSubmission{}, false, errors.New("store.EnqueueOrgIntelSubmission: org, session, purpose, level, bytes and digest are required")
	}
	if in.Trigger != OrgIntelTriggerBackground && in.Trigger != OrgIntelTriggerDeveloper {
		return OrgIntelSubmission{}, false, fmt.Errorf("store.EnqueueOrgIntelSubmission: unknown trigger %q", in.Trigger)
	}
	ok, err := s.sessionBelongsToOrg(ctx, in.OrgID, in.SessionID)
	if err != nil {
		return OrgIntelSubmission{}, false, fmt.Errorf("store.EnqueueOrgIntelSubmission: %w", err)
	}
	if !ok {
		return OrgIntelSubmission{}, false, ErrOrgIntelSessionNotThisOrg
	}
	ts := cloudFormatTime(now.UTC())
	res, err := s.db.ExecContext(ctx, `
INSERT INTO org_intel_outbox (org_id, session_id, purpose, evidence_level, trigger_kind, evidence_digest, upload_digest,
                              envelope, bytes, state, created_at, updated_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT (org_id, session_id, purpose, upload_digest) DO NOTHING`,
		in.OrgID, in.SessionID, in.Purpose, in.EvidenceLevel, in.Trigger, in.EvidenceDigest, in.UploadDigest,
		string(in.Envelope), len(in.Envelope), OrgIntelOutboxPending, ts, ts)
	if err != nil {
		return OrgIntelSubmission{}, false, fmt.Errorf("store.EnqueueOrgIntelSubmission: %w", err)
	}
	n, _ := res.RowsAffected()
	row, err := scanOrgIntelSubmission(s.db.QueryRowContext(ctx, `SELECT `+orgIntelOutboxCols+`
  FROM org_intel_outbox WHERE org_id = ? AND session_id = ? AND purpose = ? AND upload_digest = ?`,
		in.OrgID, in.SessionID, in.Purpose, in.UploadDigest).Scan)
	if err != nil {
		return OrgIntelSubmission{}, false, fmt.Errorf("store.EnqueueOrgIntelSubmission: read back: %w", err)
	}
	return row, n > 0, nil
}

// SendableOrgIntelSubmissions returns the org's pending and retry-due rows,
// oldest first.
func (s *Store) SendableOrgIntelSubmissions(ctx context.Context, orgID string, now time.Time, limit int) ([]OrgIntelSubmission, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+orgIntelOutboxCols+`
  FROM org_intel_outbox
 WHERE org_id = ? AND state IN (?, ?)
   AND (next_at = '' OR julianday(next_at) <= julianday(?))
 ORDER BY id ASC LIMIT ?`, orgID, OrgIntelOutboxPending, OrgIntelOutboxFailedRetryable, cloudFormatTime(now.UTC()), limit)
	if err != nil {
		return nil, fmt.Errorf("store.SendableOrgIntelSubmissions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []OrgIntelSubmission
	for rows.Next() {
		r, err := scanOrgIntelSubmission(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("store.SendableOrgIntelSubmissions: scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// OrgIntelSubmissionUpdate is one send attempt's result.
type OrgIntelSubmissionUpdate struct {
	State  string
	Reason string
	JobID  int64
	// NextAt is when a failed_retryable row may be sent again.
	NextAt time.Time
}

// MarkOrgIntelSubmission records a send attempt. A terminal state clears the
// held bytes (the size stays for the ledger).
func (s *Store) MarkOrgIntelSubmission(ctx context.Context, id int64, u OrgIntelSubmissionUpdate, now time.Time) error {
	switch u.State {
	case OrgIntelOutboxFailedRetryable, OrgIntelOutboxSubmitted, OrgIntelOutboxDuplicate, OrgIntelOutboxAlreadyEnriched, OrgIntelOutboxRefused:
	default:
		return fmt.Errorf("store.MarkOrgIntelSubmission: unknown state %q", u.State)
	}
	clear := 0
	if orgIntelOutboxTerminal(u.State) {
		clear = 1
	}
	_, err := s.db.ExecContext(ctx, `
UPDATE org_intel_outbox
   SET state = ?, reason = ?, job_id = CASE WHEN ? > 0 THEN ? ELSE job_id END,
       attempts = attempts + 1, next_at = ?, updated_at = ?,
       envelope = CASE WHEN ? = 1 THEN '' ELSE envelope END
 WHERE id = ?`,
		u.State, u.Reason, u.JobID, u.JobID, cloudFormatTime(u.NextAt), cloudFormatTime(now.UTC()), clear, id)
	if err != nil {
		return fmt.Errorf("store.MarkOrgIntelSubmission: %w", err)
	}
	return nil
}

// OrgIntelOutboxReasonConsentWithdrawn is the refusal reason of a queued
// submission cancelled because the developer's org-intel consent ended
// (review C156-20): withdrawn, or the machine left the org.
const OrgIntelOutboxReasonConsentWithdrawn = "consent_withdrawn"

// outboxExecer is what cancelPendingOrgIntel needs: *sql.DB or *sql.Tx.
type outboxExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// CancelPendingOrgIntelSubmissions marks every pending or retry-due row of
// orgID refused with reason and clears its held bytes, so nothing queued
// under a consent that ended can leave the machine. It returns how many rows
// it cancelled.
func (s *Store) CancelPendingOrgIntelSubmissions(ctx context.Context, orgID, reason string, now time.Time) (int, error) {
	return cancelPendingOrgIntel(ctx, s.db, orgID, reason, now)
}

func cancelPendingOrgIntel(ctx context.Context, q outboxExecer, orgID, reason string, now time.Time) (int, error) {
	if orgID == "" {
		return 0, nil
	}
	res, err := q.ExecContext(ctx, `
UPDATE org_intel_outbox
   SET state = ?, reason = ?, envelope = '', next_at = '', updated_at = ?
 WHERE org_id = ? AND state IN (?, ?)`,
		OrgIntelOutboxRefused, reason, cloudFormatTime(now.UTC()), orgID, OrgIntelOutboxPending, OrgIntelOutboxFailedRetryable)
	if err != nil {
		return 0, fmt.Errorf("store.CancelPendingOrgIntelSubmissions: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// OrgIntelSubmissions lists the org's submissions newest first (the ledger),
// optionally for one session (sessionID "" = all).
func (s *Store) OrgIntelSubmissions(ctx context.Context, orgID, sessionID string, limit int) ([]OrgIntelSubmission, error) {
	if limit <= 0 {
		limit = 50
	}
	q := `SELECT ` + orgIntelOutboxCols + ` FROM org_intel_outbox WHERE org_id = ?`
	args := []any{orgID}
	if sessionID != "" {
		q += ` AND session_id = ?`
		args = append(args, sessionID)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store.OrgIntelSubmissions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []OrgIntelSubmission
	for rows.Next() {
		r, err := scanOrgIntelSubmission(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("store.OrgIntelSubmissions: scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetOrgIntelSubmission returns one row by id within an org.
func (s *Store) GetOrgIntelSubmission(ctx context.Context, orgID string, id int64) (OrgIntelSubmission, bool, error) {
	r, err := scanOrgIntelSubmission(s.db.QueryRowContext(ctx, `SELECT `+orgIntelOutboxCols+`
  FROM org_intel_outbox WHERE org_id = ? AND id = ?`, orgID, id).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return OrgIntelSubmission{}, false, nil
	}
	if err != nil {
		return OrgIntelSubmission{}, false, fmt.Errorf("store.GetOrgIntelSubmission: %w", err)
	}
	return r, true, nil
}

// OrgIntelSubmitCandidate is a quiet org-authority session the background
// sweep may submit.
type OrgIntelSubmitCandidate struct {
	SessionID    string
	LastActionAt time.Time
	Actions      int
}

// ListOrgIntelSubmitCandidates returns ORG-authority sessions captured under
// orgID (sessions.authority_org_key, agent migration 250, D-43) and started
// at or after since, with at least minActions actions, quiet for quietFor,
// that have no submission row for this org yet (the background sweep submits
// a session once; a developer re-run is its own act). Oldest-quiet first.
// orgID must be the org enrolled now; for any other org, or on a node that is
// not enrolled, there are no candidates.
func (s *Store) ListOrgIntelSubmitCandidates(ctx context.Context, orgID string, since time.Time, quietFor time.Duration, minActions, limit int, now time.Time) ([]OrgIntelSubmitCandidate, error) {
	if limit <= 0 {
		limit = 5
	}
	key, ok, err := s.orgIntelDestinationKey(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("store.ListOrgIntelSubmitCandidates: %w", err)
	}
	if !ok {
		return nil, nil
	}
	cutoff := now.UTC().Add(-quietFor)
	rows, err := s.db.QueryContext(ctx, `
SELECT s.id, MAX(a.timestamp) AS last_action_at, COUNT(a.id)
  FROM sessions s
  JOIN actions a ON a.session_id = s.id
 WHERE s.authority = 'org'
   AND s.authority_org_key = ?
   AND s.started_at >= ?
   AND NOT EXISTS (SELECT 1 FROM org_intel_outbox o WHERE o.org_id = ? AND o.session_id = s.id)
 GROUP BY s.id
HAVING MAX(a.timestamp) <= ? AND COUNT(a.id) >= ?
 ORDER BY last_action_at ASC
 LIMIT ?`, key, cloudFormatTime(since.UTC()), orgID, timestamp(cutoff), minActions, limit)
	if err != nil {
		return nil, fmt.Errorf("store.ListOrgIntelSubmitCandidates: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []OrgIntelSubmitCandidate
	for rows.Next() {
		var (
			c    OrgIntelSubmitCandidate
			last string
		)
		if err := rows.Scan(&c.SessionID, &last, &c.Actions); err != nil {
			return nil, fmt.Errorf("store.ListOrgIntelSubmitCandidates: scan: %w", err)
		}
		c.LastActionAt = cloudParseTime(last)
		out = append(out, c)
	}
	return out, rows.Err()
}

// orgIntelDestinationKey is the authority_org_key an org-plane submission for
// orgID may carry: the key of the enrolment in force, only when orgID is that
// enrolment's org. ok=false when the node is not enrolled or is enrolled in
// another org (nothing may be submitted to orgID).
func (s *Store) orgIntelDestinationKey(ctx context.Context, orgID string) (key string, ok bool, err error) {
	if orgID == "" {
		return "", false, nil
	}
	dest, err := s.orgDestinationFor(ctx, orgID)
	switch {
	case errors.Is(err, errOrgDestinationChanged):
		return "", false, nil
	case err != nil:
		return "", false, err
	case dest.open:
		return "", false, nil
	}
	return dest.key, true, nil
}

// sessionBelongsToOrg reports whether an org-plane submission for sessionID
// may go to orgID. A session with no row here carries no captured data of
// this node and is not refused (the envelope cannot have been built from it);
// a session keyed to anything but orgID's enrolment is.
func (s *Store) sessionBelongsToOrg(ctx context.Context, orgID, sessionID string) (bool, error) {
	key, ok, err := s.orgIntelDestinationKey(ctx, orgID)
	if err != nil || !ok {
		return false, err
	}
	keys, err := s.sessionOrgKeys(ctx, []string{sessionID})
	if err != nil {
		return false, err
	}
	got, found := keys[sessionID]
	return keepAttributedRow(sessionID, found, got, orgDestination{key: key}), nil
}
