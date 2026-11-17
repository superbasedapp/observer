package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// orgoutbox.go is the store seam of the host-API client (managed-SaaS M6.4,
// cloud migrations 0058-0060; design
// docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 4.6). It owns
// every statement on org_outbox beyond M6.1a's provisioning insert, the
// worker's two writes to orgs (placement, adopting the host's create answer)
// and org_reconcile_findings. The worker runs these under WithSystem as
// sbci_worker; orgs is reached through 0059's worker-only policies.
//
// THE CLAIM RULE. A row is due when it is pending or sent, its
// next_attempt_at has passed, its lease (if any) has expired, and no OLDER
// open (pending or sent) row exists for the same org (per-org order by seq).
// ClaimOrgOutbox locks due rows FOR UPDATE SKIP LOCKED, stamps a fresh lease
// token and expiry, bumps attempts and commits before anything is sent. A
// second claimer skips the locked rows while the first transaction runs and
// sees a live lease after it commits, so two dispatchers never hold one row
// at once; the outcome is recorded only WHERE the lease token still matches.

// OrgIntent is one host-API intent to enqueue. The caller (the hostapi
// package's intent constructors) builds the payload and the deterministic
// idempotency key.
type OrgIntent struct {
	OrgID          string
	Verb           OrgOutboxVerb
	IdempotencyKey string
	LifecycleGen   int64
	Payload        []byte
}

// ErrOrgIntentInvalid means an OrgIntent cannot be written.
var ErrOrgIntentInvalid = errors.New("cloudserver/store: org outbox intent is invalid")

// ErrOrgOutboxLeaseLost means the row's lease token no longer matches: the
// lease expired and another worker claimed the row, or the row is no longer
// in flight. The caller's outcome is dropped; the row's current holder
// records its own.
var ErrOrgOutboxLeaseLost = errors.New("cloudserver/store: org outbox lease lost")

func (in OrgIntent) validate() error {
	if !slices.Contains(KnownOrgOutboxVerbs(), in.Verb) || strings.TrimSpace(in.OrgID) == "" ||
		strings.TrimSpace(in.IdempotencyKey) == "" || in.LifecycleGen < 0 {
		return ErrOrgIntentInvalid
	}
	if len(in.Payload) > 0 && !json.Valid(in.Payload) {
		return ErrOrgIntentInvalid
	}
	return nil
}

// EnqueueOrgIntentTx writes in to org_outbox inside the caller's transaction,
// the one that makes the control-plane change the intent announces, so both
// commit or neither does. It is idempotent on the key: a second enqueue of
// the same key (in the same transaction or any later one) writes nothing and
// reports false. The key is deterministic in the intent's identity
// (hostapi), so the same key means the same intent. It needs INSERT on
// org_outbox only (ON CONFLICT DO NOTHING without a conflict target), so the
// api role's provisioning grant suffices.
func EnqueueOrgIntentTx(ctx context.Context, tx pgx.Tx, in OrgIntent) (bool, error) {
	if err := in.validate(); err != nil {
		return false, fmt.Errorf("cloudserver/store.EnqueueOrgIntentTx: %w", err)
	}
	payload := in.Payload
	if len(payload) == 0 {
		payload = []byte(`{}`)
	}
	tag, err := tx.Exec(ctx,
		`INSERT INTO org_outbox (org_id, verb, idempotency_key, payload, lifecycle_gen)
		 VALUES ($1::uuid, $2, $3, $4::jsonb, $5)
		 ON CONFLICT DO NOTHING`,
		in.OrgID, string(in.Verb), in.IdempotencyKey, string(payload), in.LifecycleGen)
	if err != nil {
		return false, fmt.Errorf("cloudserver/store.EnqueueOrgIntentTx: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// EnqueueOrgIntent is EnqueueOrgIntentTx in its own system transaction, for
// callers with no other change to commit alongside (the reconciler uses
// ApplyOrgReconcile instead).
func (s *Store) EnqueueOrgIntent(ctx context.Context, in OrgIntent) (bool, error) {
	var inserted bool
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		inserted, err = EnqueueOrgIntentTx(ctx, tx, in)
		return err
	})
	if err != nil {
		return false, fmt.Errorf("cloudserver/store.EnqueueOrgIntent: %w", err)
	}
	return inserted, nil
}

// OrgOutboxClaim asks for up to Limit due rows at Now, each leased for
// LeaseTTL.
type OrgOutboxClaim struct {
	Now      time.Time
	LeaseTTL time.Duration
	Limit    int
}

// ClaimedOrgIntent is one claimed outbox row. LeaseToken fences the outcome.
type ClaimedOrgIntent struct {
	OutboxID       string
	OrgID          string
	Verb           OrgOutboxVerb
	IdempotencyKey string
	LifecycleGen   int64
	Payload        []byte
	// Attempts counts this attempt.
	Attempts   int
	HostID     string // "" until placed
	LeaseToken string
	LeaseUntil time.Time
}

// ClaimOrgOutbox leases the due rows (see THE CLAIM RULE), oldest due first.
func (s *Store) ClaimOrgOutbox(ctx context.Context, c OrgOutboxClaim) ([]ClaimedOrgIntent, error) {
	if c.Limit <= 0 || c.LeaseTTL <= 0 || c.Now.IsZero() {
		return nil, errors.New("cloudserver/store.ClaimOrgOutbox: Now, a positive LeaseTTL and Limit are required")
	}
	var out []ClaimedOrgIntent
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			WITH due AS (
				SELECT o.outbox_id
				  FROM org_outbox o
				 WHERE o.state IN ('pending', 'sent')
				   AND o.next_attempt_at <= $1::timestamptz
				   AND (o.lease_until IS NULL OR o.lease_until <= $1::timestamptz)
				   AND NOT EXISTS (
				       SELECT 1 FROM org_outbox e
				        WHERE e.org_id = o.org_id
				          AND e.state IN ('pending', 'sent')
				          AND (coalesce(e.seq, 0), e.created_at, e.outbox_id)
				            < (coalesce(o.seq, 0), o.created_at, o.outbox_id))
				 ORDER BY o.next_attempt_at, o.seq NULLS FIRST, o.outbox_id
				 LIMIT $2
				 FOR UPDATE OF o SKIP LOCKED
			)
			UPDATE org_outbox x
			   SET state = 'sent',
			       lease_token = gen_random_uuid(),
			       lease_until = $1::timestamptz + make_interval(secs => $3::double precision),
			       attempts = x.attempts + 1,
			       last_attempt_at = $1::timestamptz
			  FROM due, orgs g
			 WHERE x.outbox_id = due.outbox_id
			   AND g.org_id = x.org_id
			RETURNING x.outbox_id::text, x.org_id::text, x.verb, x.idempotency_key, x.lifecycle_gen,
			          x.payload::text, x.attempts, coalesce(g.host_id, ''), x.lease_token::text, x.lease_until`,
			c.Now, c.Limit, c.LeaseTTL.Seconds())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r ClaimedOrgIntent
			var verb, payload string
			if err := rows.Scan(&r.OutboxID, &r.OrgID, &verb, &r.IdempotencyKey, &r.LifecycleGen,
				&payload, &r.Attempts, &r.HostID, &r.LeaseToken, &r.LeaseUntil); err != nil {
				return err
			}
			r.Verb, r.Payload = OrgOutboxVerb(verb), []byte(payload)
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.ClaimOrgOutbox: %w", err)
	}
	return out, nil
}

// AssignOrgHost places orgID on hostID when the org has no host yet and
// returns the org's host either way: the first placement wins and every
// later caller learns it, so a retried create always goes to the same host.
// ErrNotFound when the org does not exist.
func (s *Store) AssignOrgHost(ctx context.Context, orgID, hostID string) (string, error) {
	if strings.TrimSpace(hostID) == "" {
		return "", errors.New("cloudserver/store.AssignOrgHost: empty host id")
	}
	var got string
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`UPDATE orgs SET host_id = $2, updated_at = now() WHERE org_id = $1::uuid AND host_id IS NULL`,
			orgID, hostID); err != nil {
			return err
		}
		err := tx.QueryRow(ctx, `SELECT coalesce(host_id, '') FROM orgs WHERE org_id = $1::uuid`, orgID).Scan(&got)
		if errors.Is(err, pgx.ErrNoRows) || isInvalidUUIDErr(err) {
			return ErrNotFound
		}
		return err
	})
	if err != nil {
		return "", fmt.Errorf("cloudserver/store.AssignOrgHost: %w", err)
	}
	return got, nil
}

// OrgOutboxResult is what an attempt did to its row.
type OrgOutboxResult string

// Outbox results.
const (
	// OutboxResultAcked: the host acted; state acked.
	OutboxResultAcked OrgOutboxResult = "acked"
	// OutboxResultRetry: back to pending until NextAttemptAt.
	OutboxResultRetry OrgOutboxResult = "retry"
	// OutboxResultParked: state failed, for an operator.
	OutboxResultParked OrgOutboxResult = "parked"
)

// OrgOutboxOutcome records one attempt's outcome under its lease.
type OrgOutboxOutcome struct {
	OutboxID   string
	LeaseToken string
	Result     OrgOutboxResult
	Now        time.Time
	// NextAttemptAt is when a retry is due (Retry only).
	NextAttemptAt time.Time
	// ErrorClass is the enum-only class ("" on ack).
	ErrorClass string
	// HostState and HostGen are what a verified answer reported (ack only;
	// HostState "" when the verb reports none).
	HostState string
	HostGen   int64
	// AdoptCreate moves a still-provisioning org to HostState and raises its
	// lifecycle_gen to HostGen, in the same transaction as the ack (the
	// answer to its create_tenant intent).
	AdoptCreate bool
}

// outcomeSQL is the fenced UPDATE per result, walked by result.
var outcomeSQL = map[OrgOutboxResult]string{
	OutboxResultAcked: `UPDATE org_outbox
		   SET state = 'acked', done_at = $3, lease_token = NULL, lease_until = NULL,
		       last_error_class = NULL, host_state = nullif($4, ''), host_lifecycle_gen = $5
		 WHERE outbox_id = $1::uuid AND lease_token = $2::uuid AND state = 'sent'
		RETURNING org_id::text`,
	OutboxResultRetry: `UPDATE org_outbox
		   SET state = 'pending', next_attempt_at = $3, lease_token = NULL, lease_until = NULL,
		       last_error_class = $4
		 WHERE outbox_id = $1::uuid AND lease_token = $2::uuid AND state = 'sent'
		RETURNING org_id::text`,
	OutboxResultParked: `UPDATE org_outbox
		   SET state = 'failed', done_at = $3, lease_token = NULL, lease_until = NULL,
		       last_error_class = $4
		 WHERE outbox_id = $1::uuid AND lease_token = $2::uuid AND state = 'sent'
		RETURNING org_id::text`,
}

// RecordOrgOutboxOutcome records o under its lease. ErrOrgOutboxLeaseLost
// when the lease token no longer matches (nothing is written).
func (s *Store) RecordOrgOutboxOutcome(ctx context.Context, o OrgOutboxOutcome) error {
	sql, ok := outcomeSQL[o.Result]
	if !ok || o.Now.IsZero() || o.OutboxID == "" || o.LeaseToken == "" {
		return fmt.Errorf("cloudserver/store.RecordOrgOutboxOutcome: %w", ErrOrgIntentInvalid)
	}
	var args []any
	switch o.Result {
	case OutboxResultAcked:
		var gen *int64
		if o.HostState != "" {
			gen = &o.HostGen
		}
		args = []any{o.OutboxID, o.LeaseToken, o.Now, o.HostState, gen}
	case OutboxResultRetry:
		args = []any{o.OutboxID, o.LeaseToken, o.NextAttemptAt, o.ErrorClass}
	default:
		args = []any{o.OutboxID, o.LeaseToken, o.Now, o.ErrorClass}
	}
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var orgID string
		err := tx.QueryRow(ctx, sql, args...).Scan(&orgID)
		if errors.Is(err, pgx.ErrNoRows) || isInvalidUUIDErr(err) {
			return ErrOrgOutboxLeaseLost
		}
		if err != nil {
			return err
		}
		if o.Result != OutboxResultAcked || !o.AdoptCreate || o.HostState == "" {
			return nil
		}
		_, err = tx.Exec(ctx,
			`UPDATE orgs SET status = $2, lifecycle_gen = greatest(lifecycle_gen, $3), updated_at = $4
			  WHERE org_id = $1::uuid AND status = 'provisioning'`,
			orgID, o.HostState, o.HostGen, o.Now)
		return err
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.RecordOrgOutboxOutcome: %w", err)
	}
	return nil
}

// RequeueParkedOrgIntent moves a parked (failed) row back to pending, due at
// now, keeping its key and attempt count: the operator's lever after fixing
// what the host refused. ErrNotFound when no parked row has that id.
func (s *Store) RequeueParkedOrgIntent(ctx context.Context, outboxID string, now time.Time) error {
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE org_outbox SET state = 'pending', next_attempt_at = $2, done_at = NULL, last_error_class = NULL
			  WHERE outbox_id = $1::uuid AND state = 'failed'`, outboxID, now)
		if isInvalidUUIDErr(err) || (err == nil && tag.RowsAffected() == 0) {
			return ErrNotFound
		}
		return err
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.RequeueParkedOrgIntent: %w", err)
	}
	return nil
}

// OrgReconcileView is one org as the reconciler reads it.
type OrgReconcileView struct {
	OrgID        string
	DisplayName  string
	Status       string
	LifecycleGen int64
	HostID       string
	// OpenIntent is true when a pending or sent outbox row exists for the org.
	OpenIntent bool
}

// ListOrgsForReconcile returns up to limit orgs with an id above afterOrgID
// ("" for the first page), ordered by id.
func (s *Store) ListOrgsForReconcile(ctx context.Context, afterOrgID string, limit int) ([]OrgReconcileView, error) {
	if limit <= 0 {
		return nil, errors.New("cloudserver/store.ListOrgsForReconcile: limit must be positive")
	}
	if afterOrgID == "" {
		afterOrgID = "00000000-0000-0000-0000-000000000000"
	}
	var out []OrgReconcileView
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT g.org_id::text, g.display_name, g.status, g.lifecycle_gen, coalesce(g.host_id, ''),
			       EXISTS (SELECT 1 FROM org_outbox o WHERE o.org_id = g.org_id AND o.state IN ('pending', 'sent'))
			  FROM orgs g
			 WHERE g.org_id > $1::uuid
			 ORDER BY g.org_id
			 LIMIT $2`, afterOrgID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v OrgReconcileView
			if err := rows.Scan(&v.OrgID, &v.DisplayName, &v.Status, &v.LifecycleGen, &v.HostID, &v.OpenIntent); err != nil {
				return err
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.ListOrgsForReconcile: %w", err)
	}
	return out, nil
}

// OrgReconcileFinding is one open mismatch the reconciler saw.
type OrgReconcileFinding struct {
	Kind         string
	DesiredState string
	DesiredGen   int64
	// Served is nil when the host was not asked or did not answer.
	Served *bool
	// HostState, HostGen and Health are the host's verified answer (empty /
	// nil when absent).
	HostState string
	HostGen   *int64
	Health    string
	// CorrectionKey is the idempotency key of the correction this finding
	// enqueued, "" when alert-only.
	CorrectionKey string
}

// OrgReconcileUpdate is one org's reconciliation pass.
type OrgReconcileUpdate struct {
	OrgID      string
	Now        time.Time
	Findings   []OrgReconcileFinding
	Correction *OrgIntent
}

// ApplyOrgReconcile writes one org's pass in one transaction: it enqueues the
// correction (idempotent on its key), opens or refreshes each finding (one
// open row per kind) and resolves the org's other open findings. It reports
// whether the correction wrote a new outbox row.
func (s *Store) ApplyOrgReconcile(ctx context.Context, u OrgReconcileUpdate) (bool, error) {
	if u.OrgID == "" || u.Now.IsZero() {
		return false, fmt.Errorf("cloudserver/store.ApplyOrgReconcile: %w", ErrOrgIntentInvalid)
	}
	var enqueued bool
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if u.Correction != nil {
			var err error
			if enqueued, err = EnqueueOrgIntentTx(ctx, tx, *u.Correction); err != nil {
				return err
			}
		}
		kinds := make([]string, 0, len(u.Findings))
		for _, f := range u.Findings {
			kinds = append(kinds, f.Kind)
			if _, err := tx.Exec(ctx, `
				INSERT INTO org_reconcile_findings
				       (org_id, kind, desired_state, desired_gen, served, host_state, host_gen, health,
				        correction_key, first_seen, last_seen)
				VALUES ($1::uuid, $2, $3, $4, $5, nullif($6, ''), $7, nullif($8, ''), nullif($9, ''), $10, $10)
				ON CONFLICT (org_id, kind) WHERE resolved_at IS NULL DO UPDATE
				   SET desired_state = EXCLUDED.desired_state, desired_gen = EXCLUDED.desired_gen,
				       served = EXCLUDED.served, host_state = EXCLUDED.host_state, host_gen = EXCLUDED.host_gen,
				       health = EXCLUDED.health,
				       correction_key = coalesce(EXCLUDED.correction_key, org_reconcile_findings.correction_key),
				       last_seen = EXCLUDED.last_seen, seen_count = org_reconcile_findings.seen_count + 1`,
				u.OrgID, f.Kind, f.DesiredState, f.DesiredGen, f.Served, f.HostState, f.HostGen, f.Health,
				f.CorrectionKey, u.Now); err != nil {
				return fmt.Errorf("finding %s: %w", f.Kind, err)
			}
		}
		_, err := tx.Exec(ctx, `
			UPDATE org_reconcile_findings SET resolved_at = $3
			 WHERE org_id = $1::uuid AND resolved_at IS NULL AND NOT (kind = ANY($2))`,
			u.OrgID, kinds, u.Now)
		return err
	})
	if err != nil {
		return false, fmt.Errorf("cloudserver/store.ApplyOrgReconcile: %w", err)
	}
	return enqueued, nil
}
