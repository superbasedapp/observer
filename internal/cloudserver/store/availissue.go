package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// availissue.go is the one store seam of the availability envelope's issue
// requests and per-host delivery state (cloud migration 0154; managed-SaaS
// M6.3; ledger STAFF-8). The staff process records a request (with its
// staff_actions row, in one transaction); the worker reads the inputs,
// finishes the request, stores the signed envelope together with the
// request's outcome, and records each host's answer. Every staff statement
// runs in WithStaff, every worker statement in WithSystem.

// Issue request states (the availability_issue_requests.state CHECK).
const (
	IssueStatePending = "pending"
	IssueStateIssued  = "issued"
	IssueStateStale   = "stale"
	IssueStateFailed  = "failed"
)

// Delivery states (the availability_deliveries.state CHECK).
const (
	DeliveryDelivered = "delivered"
	DeliveryRetry     = "retry"
	DeliveryRefused   = "refused"
)

// Availability issue errors.
var (
	// ErrIssuePending means another issue request is still pending.
	ErrIssuePending = errors.New("cloudserver/store: an availability issue request is already pending")
	// ErrIssueNotPending means the request was finished by someone else.
	ErrIssueNotPending = errors.New("cloudserver/store: the availability issue request is no longer pending")
	// ErrIssueInvalid means a request, outcome or delivery field is malformed.
	ErrIssueInvalid = errors.New("cloudserver/store: invalid availability issue or delivery")
)

// AvailabilityIssueRequest is one issue request.
type AvailabilityIssueRequest struct {
	RequestID     string     `json:"request_id"`
	RequestedBy   string     `json:"requested_by"`
	Reason        string     `json:"reason"`
	InputsDigest  string     `json:"inputs_digest"`
	BaseVersion   int64      `json:"base_version"`
	State         string     `json:"state"`
	ResultVersion int64      `json:"result_version,omitempty"`
	ErrorClass    string     `json:"error_class,omitempty"`
	RequestedAt   time.Time  `json:"requested_at"`
	DoneAt        *time.Time `json:"done_at,omitempty"`
}

// AvailabilityDelivery is one host's delivery state.
type AvailabilityDelivery struct {
	HostID           string    `json:"host_id"`
	Version          int64     `json:"version"`
	AttemptedVersion int64     `json:"attempted_version"`
	State            string    `json:"state"`
	Attempts         int       `json:"attempts"`
	ErrorClass       string    `json:"error_class,omitempty"`
	UpdatedAt        time.Time `json:"updated_at"`
}

var (
	digestRE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	errorClassRE = regexp.MustCompile(`^[a-z0-9_:.-]{1,64}$`)
	hostIDRE     = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// AvailabilityIssueInput is what a staff member asks for.
type AvailabilityIssueInput struct {
	// Reason is why (staffauth.ValidateReason).
	Reason string
	// InputsDigest is availcompose.Digest of the inputs previewed.
	InputsDigest string
	// BaseVersion is the newest issued version the preview was against.
	BaseVersion int64
	// Changes is how many rows the preview showed changing (logged only).
	Changes int
}

const issueRequestColumns = `request_id::text, requested_by, reason, inputs_digest, base_version, state,
	coalesce(result_version, 0), coalesce(error_class, ''), requested_at, done_at`

func scanIssueRequest(row pgx.Row) (AvailabilityIssueRequest, error) {
	var r AvailabilityIssueRequest
	err := row.Scan(&r.RequestID, &r.RequestedBy, &r.Reason, &r.InputsDigest, &r.BaseVersion, &r.State,
		&r.ResultVersion, &r.ErrorClass, &r.RequestedAt, &r.DoneAt)
	return r, err
}

// RequestAvailabilityIssue records staff member staffID's issue request and
// its staff_actions row in one transaction. ErrIssuePending when one is
// already pending.
func (s *Store) RequestAvailabilityIssue(ctx context.Context, staffID string, in AvailabilityIssueInput, now time.Time) (AvailabilityIssueRequest, error) {
	reason, err := staffauth.ValidateReason(in.Reason)
	if err != nil {
		return AvailabilityIssueRequest{}, fmt.Errorf("cloudserver/store.RequestAvailabilityIssue: %w", err)
	}
	if !digestRE.MatchString(in.InputsDigest) || in.BaseVersion < 0 || in.Changes < 0 {
		return AvailabilityIssueRequest{}, fmt.Errorf("cloudserver/store.RequestAvailabilityIssue: %w", ErrIssueInvalid)
	}
	now = nowOr(now)
	out := AvailabilityIssueRequest{
		RequestID: uuid.NewString(), RequestedBy: staffauth.Actor(staffID), Reason: reason,
		InputsDigest: in.InputsDigest, BaseVersion: in.BaseVersion, State: IssueStatePending, RequestedAt: now.UTC(),
	}
	err = s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO availability_issue_requests (request_id, requested_by, reason, inputs_digest, base_version, state, requested_at)
			 VALUES ($1::uuid, $2, $3, $4, $5, 'pending', $6)`,
			out.RequestID, out.RequestedBy, reason, in.InputsDigest, in.BaseVersion, out.RequestedAt); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return ErrIssuePending
			}
			return fmt.Errorf("insert request: %w", err)
		}
		return insertStaffAction(ctx, tx, staffActionRow{
			at: now, actor: staffauth.Actor(staffID), verb: staffauth.VerbAvailabilityIssueRequested,
			subject: staffID, target: "availability:issue",
			detail: map[string]any{"request_id": out.RequestID, "inputs_digest": in.InputsDigest, "base_version": in.BaseVersion, "changes": in.Changes},
			reason: reason, result: "ok",
		})
	})
	if err != nil {
		if errors.Is(err, ErrIssuePending) {
			return AvailabilityIssueRequest{}, ErrIssuePending
		}
		return AvailabilityIssueRequest{}, fmt.Errorf("cloudserver/store.RequestAvailabilityIssue: %w", err)
	}
	return out, nil
}

// IssueClassCancelled is the error class of a request a staff member
// cancelled while it was pending (it is then failed).
const IssueClassCancelled = "cancelled"

// CancelAvailabilityIssue moves the pending request requestID to failed with
// error class cancelled and writes its staff_actions row, in one transaction
// (staff; cloud 0154's policy allows that one move and nothing else). It is
// the way out when no worker will finish the request (its availability loops
// are off), which would otherwise refuse every later issue.
// ErrIssueNotPending when no request with that id is pending (finished by
// the worker, cancelled already, or unknown); ErrIssueInvalid for a malformed
// id.
func (s *Store) CancelAvailabilityIssue(ctx context.Context, staffID, requestID, reason string, now time.Time) (AvailabilityIssueRequest, error) {
	reason, err := staffauth.ValidateReason(reason)
	if err != nil {
		return AvailabilityIssueRequest{}, fmt.Errorf("cloudserver/store.CancelAvailabilityIssue: %w", err)
	}
	id, err := uuid.Parse(requestID)
	if err != nil {
		return AvailabilityIssueRequest{}, fmt.Errorf("cloudserver/store.CancelAvailabilityIssue: %w", ErrIssueInvalid)
	}
	now = nowOr(now)
	var out AvailabilityIssueRequest
	err = s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		r, err := scanIssueRequest(tx.QueryRow(ctx,
			`UPDATE availability_issue_requests SET state = 'failed', error_class = $2, done_at = $3
			  WHERE request_id = $1::uuid AND state = 'pending'
			 RETURNING `+issueRequestColumns,
			id.String(), IssueClassCancelled, now.UTC()))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrIssueNotPending
		}
		if err != nil {
			return fmt.Errorf("cancel request: %w", err)
		}
		out = r
		return insertStaffAction(ctx, tx, staffActionRow{
			at: now, actor: staffauth.Actor(staffID), verb: staffauth.VerbAvailabilityIssueCancelled,
			subject: staffID, target: "availability:issue",
			detail: map[string]any{"request_id": r.RequestID, "requested_by": r.RequestedBy, "inputs_digest": r.InputsDigest, "base_version": r.BaseVersion},
			reason: reason, result: "ok",
		})
	})
	if err != nil {
		if errors.Is(err, ErrIssueNotPending) {
			return AvailabilityIssueRequest{}, ErrIssueNotPending
		}
		return AvailabilityIssueRequest{}, fmt.Errorf("cloudserver/store.CancelAvailabilityIssue: %w", err)
	}
	return out, nil
}

// AvailabilityIssueState is what the staff console shows about issuing: the
// pending request, the newest finished one, and every host's delivery state.
type AvailabilityIssueState struct {
	Pending    *AvailabilityIssueRequest
	Last       *AvailabilityIssueRequest
	Deliveries []AvailabilityDelivery
}

// StaffAvailabilityIssueState reads the issue and delivery state as staff.
func (s *Store) StaffAvailabilityIssueState(ctx context.Context) (AvailabilityIssueState, error) {
	var out AvailabilityIssueState
	err := s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = issueStateTx(ctx, tx)
		return err
	})
	if err != nil {
		return AvailabilityIssueState{}, fmt.Errorf("cloudserver/store.StaffAvailabilityIssueState: %w", err)
	}
	return out, nil
}

func issueStateTx(ctx context.Context, tx pgx.Tx) (AvailabilityIssueState, error) {
	out := AvailabilityIssueState{Deliveries: []AvailabilityDelivery{}}
	for _, q := range []struct {
		query string
		dst   **AvailabilityIssueRequest
	}{
		{`SELECT ` + issueRequestColumns + ` FROM availability_issue_requests WHERE state = 'pending'`, &out.Pending},
		{`SELECT ` + issueRequestColumns + ` FROM availability_issue_requests WHERE state <> 'pending'
		   ORDER BY done_at DESC, requested_at DESC, request_id DESC LIMIT 1`, &out.Last},
	} {
		r, err := scanIssueRequest(tx.QueryRow(ctx, q.query))
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return out, fmt.Errorf("read requests: %w", err)
		default:
			*q.dst = &r
		}
	}
	ds, err := deliveriesTx(ctx, tx)
	if err != nil {
		return out, err
	}
	out.Deliveries = ds
	return out, nil
}

func deliveriesTx(ctx context.Context, tx pgx.Tx) ([]AvailabilityDelivery, error) {
	rows, err := tx.Query(ctx,
		`SELECT host_id, version, attempted_version, state, attempts, coalesce(error_class, ''), updated_at
		   FROM availability_deliveries ORDER BY host_id`)
	if err != nil {
		return nil, fmt.Errorf("read deliveries: %w", err)
	}
	defer rows.Close()
	out := []AvailabilityDelivery{}
	for rows.Next() {
		var d AvailabilityDelivery
		if err := rows.Scan(&d.HostID, &d.Version, &d.AttemptedVersion, &d.State, &d.Attempts, &d.ErrorClass, &d.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan delivery: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// PendingAvailabilityIssue returns the pending request (worker), or
// ErrNotFound.
func (s *Store) PendingAvailabilityIssue(ctx context.Context) (AvailabilityIssueRequest, error) {
	var r AvailabilityIssueRequest
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		r, err = scanIssueRequest(tx.QueryRow(ctx,
			`SELECT `+issueRequestColumns+` FROM availability_issue_requests WHERE state = 'pending'`))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return AvailabilityIssueRequest{}, ErrNotFound
	}
	if err != nil {
		return AvailabilityIssueRequest{}, fmt.Errorf("cloudserver/store.PendingAvailabilityIssue: %w", err)
	}
	return r, nil
}

// AvailabilityInputsForIssue reads every availability input as the worker
// (the policy availability_inputs_worker_read, cloud 0070).
func (s *Store) AvailabilityInputsForIssue(ctx context.Context) ([]AvailabilityInputRow, error) {
	out := []AvailabilityInputRow{}
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT section, key, value, reason, author, updated_at FROM availability_inputs ORDER BY section, key`)
		if err != nil {
			return fmt.Errorf("list inputs: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var r AvailabilityInputRow
			var value []byte
			if err := rows.Scan(&r.Section, &r.Key, &value, &r.Reason, &r.Author, &r.UpdatedAt); err != nil {
				return fmt.Errorf("scan input: %w", err)
			}
			r.Value = value
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.AvailabilityInputsForIssue: %w", err)
	}
	return out, nil
}

// finishStates are the outcomes FinishAvailabilityIssue may record (issued
// goes through IssueAvailabilityDocument, with its document).
var finishStates = []string{IssueStateStale, IssueStateFailed}

// FinishAvailabilityIssue moves a pending request to stale or failed with an
// error class (worker). ErrIssueNotPending when it is no longer pending.
func (s *Store) FinishAvailabilityIssue(ctx context.Context, requestID, state, errorClass string, now time.Time) error {
	okState := false
	for _, st := range finishStates {
		okState = okState || st == state
	}
	if !okState || !errorClassRE.MatchString(errorClass) {
		return fmt.Errorf("cloudserver/store.FinishAvailabilityIssue: %w", ErrIssueInvalid)
	}
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE availability_issue_requests SET state = $2, error_class = $3, done_at = $4
			  WHERE request_id = $1::uuid AND state = 'pending'`,
			requestID, state, errorClass, nowOr(now).UTC())
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrIssueNotPending
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.FinishAvailabilityIssue: %w", err)
	}
	return nil
}

// IssueAvailabilityDocument stores a signed envelope and marks the pending
// request requestID issued with its version, in ONE transaction (worker): an
// envelope is never stored for a request that another worker already
// finished, and a request is never marked issued without its envelope. The
// document is checked as InsertAvailabilityDocument checks it; a version not
// above the stream's highest (or its floor) is refused with an error wrapping
// platformcontract.ErrVersionNotNewer, and nothing is written.
func (s *Store) IssueAvailabilityDocument(ctx context.Context, requestID string, doc platformcontract.AvailabilityDocument, issuedBy string, issuedAt time.Time) error {
	if err := checkStoredDocument(platformcontract.KindAvailability, platformcontract.AvailabilityScope, doc.Version, doc.Body, doc.Signature, doc.KeyID, issuedBy); err != nil {
		return fmt.Errorf("cloudserver/store.IssueAvailabilityDocument: %w", err)
	}
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := insertAvailabilityDocTx(ctx, tx, doc, issuedBy, issuedAt); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx,
			`UPDATE availability_issue_requests SET state = 'issued', result_version = $2, done_at = $3
			  WHERE request_id = $1::uuid AND state = 'pending'`,
			requestID, doc.Version, issuedAt.UTC())
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrIssueNotPending
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.IssueAvailabilityDocument: %w", err)
	}
	return nil
}

// AvailabilityDeliveries reads every host's delivery state (worker).
func (s *Store) AvailabilityDeliveries(ctx context.Context) ([]AvailabilityDelivery, error) {
	var out []AvailabilityDelivery
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = deliveriesTx(ctx, tx)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.AvailabilityDeliveries: %w", err)
	}
	return out, nil
}

// deliveryStates is the availability_deliveries.state vocabulary.
var deliveryStates = []string{DeliveryDelivered, DeliveryRetry, DeliveryRefused}

// RecordAvailabilityDelivery writes one host's delivery state (worker). The
// version in force never goes down: a host answers with the version it
// holds, which only rises.
func (s *Store) RecordAvailabilityDelivery(ctx context.Context, d AvailabilityDelivery) error {
	okState := false
	for _, st := range deliveryStates {
		okState = okState || st == d.State
	}
	if !okState || !hostIDRE.MatchString(d.HostID) || d.Version < 0 || d.AttemptedVersion <= 0 || d.Attempts < 0 ||
		(d.ErrorClass != "" && !errorClassRE.MatchString(d.ErrorClass)) {
		return fmt.Errorf("cloudserver/store.RecordAvailabilityDelivery: %w", ErrIssueInvalid)
	}
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO availability_deliveries (host_id, version, attempted_version, state, attempts, error_class, updated_at)
			 VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7)
			 ON CONFLICT (host_id) DO UPDATE
			   SET version = GREATEST(availability_deliveries.version, EXCLUDED.version),
			       attempted_version = EXCLUDED.attempted_version, state = EXCLUDED.state,
			       attempts = EXCLUDED.attempts, error_class = EXCLUDED.error_class,
			       updated_at = EXCLUDED.updated_at`,
			d.HostID, d.Version, d.AttemptedVersion, d.State, d.Attempts, d.ErrorClass, nowOr(d.UpdatedAt).UTC())
		return err
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.RecordAvailabilityDelivery: %w", err)
	}
	return nil
}
