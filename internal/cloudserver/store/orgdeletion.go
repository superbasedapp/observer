package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/deletionjournal"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/orgdeletion"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// orgdeletion.go is the store seam of org deletion and of account deletion
// with orgs (managed-SaaS plan 07 M6.9, the control-plane half of M7a.1;
// cloud migrations 0120-0121). It owns every statement on
// org_deletion_requests, account_deletion_followups and
// org_member_departure_notices, and the deletion driver's writes to orgs,
// org_members, oidc_clients and oidc_codes.
//
// The driver (internal/cloudserver/orgdeletion) runs these under WithSystem
// as sbci_worker; orgs and org_members are reached through the worker
// policies of 0059 and 0121. The console reaches org_deletion_requests only
// through the 0120 definer functions (OpenOrgDeletion, CancelOrgDeletion,
// OrgDeletionStatus), the staff console through WithStaff.
//
// THE COMPARE-AND-SET RULE. Every transition moves a request from the step
// the driver read to the next one only WHERE the row is still at that step,
// and does its other writes in the same transaction only if it moved the
// row. A step run twice, or by two workers at once, does its work once.

var (
	_ orgdeletion.OrgStore     = (*Store)(nil)
	_ orgdeletion.AccountStore = (*Store)(nil)
)

// ErrOrgDeletionRefused is the sentinel a refused console deletion request or
// cancel wraps; the error is an *OrgDeletionRefusal naming the outcome.
var ErrOrgDeletionRefused = errors.New("cloudserver/store: org deletion refused")

// OrgDeletionRefusal is a refused console request: Outcome is the definer
// function's word (not_owner, deletion_open, org_not_deletable,
// not_cancellable, none).
type OrgDeletionRefusal struct{ Outcome string }

func (e *OrgDeletionRefusal) Error() string {
	return "cloudserver/store: org deletion refused: " + e.Outcome
}

// Unwrap makes errors.Is(err, ErrOrgDeletionRefused) true.
func (e *OrgDeletionRefusal) Unwrap() error { return ErrOrgDeletionRefused }

// OrgDeletionView is one org deletion request as the console shows it.
type OrgDeletionView struct {
	RequestID     string
	State         string
	Step          string
	Origin        string
	RequestedAt   time.Time
	PurgeAfter    time.Time
	CanceledAt    *time.Time
	DoneAt        *time.Time
	BlockedReason string
}

// OpenOrgDeletion opens an owner's cooling-off request for org, ending at
// purgeAfter, as accountID (sbci_portal_org_deletion_open: the caller must be
// the org's owner, the org a team (cloud 0140, FR-11), active or suspended,
// no request open, and the window at least 14 days). A refusal is an
// *OrgDeletionRefusal. The console route opens through
// OpenOrgDeletionWithStepUp; this form is for callers that proved the
// person otherwise (a dev broker credential, a fresh passkey).
func (s *Store) OpenOrgDeletion(ctx context.Context, accountID, orgID string, purgeAfter time.Time) (string, error) {
	return s.openOrgDeletion(ctx, accountID, orgID, purgeAfter, nil, time.Time{})
}

// OrgDeletionStepUp is the one-use step-up authorization an org deletion
// consumes (FR-23): minted for the session's account with the deletion
// action by the WorkOS step-up leg.
type OrgDeletionStepUp struct {
	SessionID       string
	AuthorizationID string
}

// OpenOrgDeletionWithStepUp is OpenOrgDeletion that consumes su in the same
// transaction: a refused open rolls the authorization back unconsumed, and a
// consumed one opens exactly one deletion. ErrStepUpInvalid when su does not
// match the account, the session and the deletion action, or is expired or
// spent.
func (s *Store) OpenOrgDeletionWithStepUp(ctx context.Context, accountID, orgID string, purgeAfter time.Time, su OrgDeletionStepUp, now time.Time) (string, error) {
	return s.openOrgDeletion(ctx, accountID, orgID, purgeAfter, &su, now)
}

func (s *Store) openOrgDeletion(ctx context.Context, accountID, orgID string, purgeAfter time.Time, su *OrgDeletionStepUp, now time.Time) (string, error) {
	if now.IsZero() {
		now = time.Now()
	}
	var id string
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		if su != nil {
			if err := consumeStepUpTx(ctx, tx, accountID, su.SessionID, StepUpActionDeletion, su.AuthorizationID, now); err != nil {
				return err
			}
		}
		var outcome string
		var rid *string
		if err := tx.QueryRow(ctx, `SELECT outcome, request_id::text FROM sbci_portal_org_deletion_open($1::uuid, $2)`,
			orgID, purgeAfter).Scan(&outcome, &rid); err != nil {
			return err
		}
		if outcome != "created" || rid == nil {
			// Returned as the error so the step-up's consumption rolls back.
			return &OrgDeletionRefusal{Outcome: outcome}
		}
		id = *rid
		return nil
	})
	var ref *OrgDeletionRefusal
	switch {
	case errors.As(err, &ref):
		return "", ref
	case errors.Is(err, ErrStepUpInvalid):
		return "", ErrStepUpInvalid
	case isInvalidUUIDErr(err):
		return "", &OrgDeletionRefusal{Outcome: "not_owner"}
	case err != nil:
		return "", fmt.Errorf("cloudserver/store.OpenOrgDeletion: %w", err)
	}
	return id, nil
}

// SessionPasskeyUse reads, for the org deletion's step-up (FR-23), whether
// the account has an active passkey and when this session last completed its
// second factor with one (zero: never, or with a recovery code). It reads
// the same rows as PortalSecondFactorState, in the account's context.
func (s *Store) SessionPasskeyUse(ctx context.Context, accountID, sessionID string) (bool, time.Time, error) {
	var enrolled bool
	var at *time.Time
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM portal_passkeys p WHERE p.account_id = $1::uuid AND p.revoked_at IS NULL),
			        (SELECT b.second_factor_at FROM browser_sessions b
			          WHERE b.account_id = $1::uuid AND b.id = $2::uuid AND b.revoked_at IS NULL
			            AND b.second_factor_method = 'passkey')`,
			accountID, sessionID).Scan(&enrolled, &at)
		if isInvalidUUIDErr(err) {
			return nil
		}
		return err
	})
	if err != nil {
		return false, time.Time{}, fmt.Errorf("cloudserver/store.SessionPasskeyUse: %w", err)
	}
	if at == nil {
		return enrolled, time.Time{}, nil
	}
	return enrolled, at.UTC(), nil
}

// BlockedDeletions counts the org deletion requests and account follow-ups
// that are blocked now (the worker's alert, FR-1: a blocked request leaves
// the due queue, so only a count of the table shows it is still there).
func (s *Store) BlockedDeletions(ctx context.Context) (orgs, followups int, err error) {
	err = s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM org_deletion_requests WHERE state = 'blocked'),
			        (SELECT count(*) FROM account_deletion_followups WHERE state = 'blocked')`).Scan(&orgs, &followups)
	})
	if err != nil {
		return 0, 0, fmt.Errorf("cloudserver/store.BlockedDeletions: %w", err)
	}
	return orgs, followups, nil
}

// CancelOrgDeletion cancels org's cooling-off request as accountID (an
// owner). Canceling a request already canceled succeeds; a refusal is an
// *OrgDeletionRefusal (not_owner, not_cancellable, none).
func (s *Store) CancelOrgDeletion(ctx context.Context, accountID, orgID string) error {
	var outcome string
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT sbci_portal_org_deletion_cancel($1::uuid)`, orgID).Scan(&outcome)
	})
	if isInvalidUUIDErr(err) {
		return &OrgDeletionRefusal{Outcome: "not_owner"}
	}
	if err != nil {
		return fmt.Errorf("cloudserver/store.CancelOrgDeletion: %w", err)
	}
	if outcome != "canceled" {
		return &OrgDeletionRefusal{Outcome: outcome}
	}
	return nil
}

// OrgDeletionStatus returns org's newest deletion request for a member
// (ok=false when there is none or the caller is not a member).
func (s *Store) OrgDeletionStatus(ctx context.Context, accountID, orgID string) (OrgDeletionView, bool, error) {
	var v OrgDeletionView
	var blocked *string
	found := false
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT request_id::text, state, step, origin, created_at, purge_after, canceled_at, done_at, blocked_reason
			  FROM sbci_portal_org_deletion_status($1::uuid)`, orgID).
			Scan(&v.RequestID, &v.State, &v.Step, &v.Origin, &v.RequestedAt, &v.PurgeAfter, &v.CanceledAt, &v.DoneAt, &blocked)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		found = err == nil
		return err
	})
	if isInvalidUUIDErr(err) {
		return OrgDeletionView{}, false, nil
	}
	if err != nil {
		return OrgDeletionView{}, false, fmt.Errorf("cloudserver/store.OrgDeletionStatus: %w", err)
	}
	if blocked != nil {
		v.BlockedReason = *blocked
	}
	return v, found, nil
}

// OrgDepartureNotices returns the times of org's member-departure notices of
// the last 90 days, for an admin (empty for anyone else).
func (s *Store) OrgDepartureNotices(ctx context.Context, accountID, orgID string) ([]time.Time, error) {
	var out []time.Time
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT created_at FROM sbci_portal_org_departure_notices($1::uuid)`, orgID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t time.Time
			if err := rows.Scan(&t); err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	if isInvalidUUIDErr(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.OrgDepartureNotices: %w", err)
	}
	return out, nil
}

// OrgLastSeatDay returns the newest usage day of org that reported a seat in
// use, for a member (zero when none). The cooling-off window reads it. It
// reads every kept day (cloud 0140 sbci_portal_org_last_seat_day), not only
// the newest: a zero-seat newest day no longer hides an earlier seat day
// (FR-23).
func (s *Store) OrgLastSeatDay(ctx context.Context, accountID, orgID string) (time.Time, error) {
	var day *time.Time
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT sbci_portal_org_last_seat_day($1::uuid)`, orgID).Scan(&day)
	})
	if err != nil && !isInvalidUUIDErr(err) {
		return time.Time{}, fmt.Errorf("cloudserver/store.OrgLastSeatDay: %w", err)
	}
	if day == nil {
		return time.Time{}, nil
	}
	return *day, nil
}

// --- the driver's org seam (sbci_worker) ---------------------------------

const orgRequestColumns = `request_id::text, org_id::text, state, step, origin, requested_by::text, purge_after,
       coalesce(purge_gen, 0), attempts, step_entered_at`

func scanOrgRequest(row pgx.Row) (orgdeletion.OrgRequest, error) {
	var r orgdeletion.OrgRequest
	var step, origin string
	err := row.Scan(&r.RequestID, &r.OrgID, &r.State, &step, &origin, &r.RequestedBy, &r.PurgeAfter, &r.PurgeGen, &r.Attempts, &r.StepEnteredAt)
	r.Step, r.Origin = orgdeletion.Step(step), orgdeletion.Origin(origin)
	return r, err
}

// DueOrgRequests implements orgdeletion.OrgStore.
func (s *Store) DueOrgRequests(ctx context.Context, now time.Time, limit int) ([]orgdeletion.OrgRequest, error) {
	var out []orgdeletion.OrgRequest
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+orgRequestColumns+`
			  FROM org_deletion_requests
			 WHERE step <> 'done' AND state <> 'blocked' AND next_attempt_at <= $1
			 ORDER BY next_attempt_at
			 LIMIT $2`, now, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanOrgRequest(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.DueOrgRequests: %w", err)
	}
	return out, nil
}

// OpenOrgRequest implements orgdeletion.OrgStore.
func (s *Store) OpenOrgRequest(ctx context.Context, orgID string) (orgdeletion.OrgRequest, bool, error) {
	var r orgdeletion.OrgRequest
	found := false
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		r, err = scanOrgRequest(tx.QueryRow(ctx, `SELECT `+orgRequestColumns+`
			  FROM org_deletion_requests WHERE org_id = $1::uuid AND step <> 'done'`, orgID))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		found = err == nil
		return err
	})
	if isInvalidUUIDErr(err) {
		return orgdeletion.OrgRequest{}, false, nil
	}
	if err != nil {
		return orgdeletion.OrgRequest{}, false, fmt.Errorf("cloudserver/store.OpenOrgRequest: %w", err)
	}
	return r, found, nil
}

// orgFactsTx reads the org and, when lock, locks its row.
func orgFactsTx(ctx context.Context, tx pgx.Tx, orgID string, lock bool) (orgdeletion.OrgFacts, error) {
	var f orgdeletion.OrgFacts
	q := `SELECT kind, status, lifecycle_gen, coalesce(host_id, '') FROM orgs WHERE org_id = $1::uuid`
	if lock {
		q += ` FOR UPDATE`
	}
	err := tx.QueryRow(ctx, q, orgID).Scan(&f.Kind, &f.Status, &f.Gen, &f.HostID)
	if errors.Is(err, pgx.ErrNoRows) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	f.Found = true
	return f, nil
}

// OrgFacts implements orgdeletion.OrgStore.
func (s *Store) OrgFacts(ctx context.Context, orgID string) (orgdeletion.OrgFacts, error) {
	var f orgdeletion.OrgFacts
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		if f, err = orgFactsTx(ctx, tx, orgID, false); err != nil || !f.Found {
			return err
		}
		err = tx.QueryRow(ctx, `SELECT paddle_subscription_id, status FROM sbci_org_subscription($1::uuid)`, orgID).
			Scan(&f.Subscription.ID, &f.Subscription.Status)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	if isInvalidUUIDErr(err) {
		return orgdeletion.OrgFacts{}, nil
	}
	if err != nil {
		return orgdeletion.OrgFacts{}, fmt.Errorf("cloudserver/store.OrgFacts: %w", err)
	}
	return f, nil
}

// moveOrgTx is the compare-and-set: it moves the request from step from to
// step to (with extra assignments) and reports whether it did. The step's
// start (step_entered_at) is now.
func moveOrgTx(ctx context.Context, tx pgx.Tx, requestID string, from, to orgdeletion.Step, now time.Time, extra string, args ...any) (bool, error) {
	all := append([]any{requestID, string(from), string(to), now}, args...)
	tag, err := tx.Exec(ctx, `UPDATE org_deletion_requests
		   SET step = $3, updated_at = $4, next_attempt_at = $4, step_entered_at = $4, attempts = 0, last_error_class = NULL`+extra+`
		 WHERE request_id = $1::uuid AND step = $2`, all...)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// enqueueIntentsTx writes host-API intents in order.
func enqueueIntentsTx(ctx context.Context, tx pgx.Tx, intents ...hostapi.Intent) error {
	for _, in := range intents {
		if _, err := EnqueueOrgIntentTx(ctx, tx, OrgIntent{
			OrgID: in.OrgID, Verb: OrgOutboxVerb(in.Verb), IdempotencyKey: in.IdempotencyKey,
			LifecycleGen: in.LifecycleGen, Payload: in.Payload,
		}); err != nil {
			return err
		}
	}
	return nil
}

// setOrgStateTx moves the org to state at gen.
func setOrgStateTx(ctx context.Context, tx pgx.Tx, orgID, state string, gen int64, now time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE orgs SET status = $2, lifecycle_gen = greatest(lifecycle_gen, $3), updated_at = $4
		WHERE org_id = $1::uuid`, orgID, state, gen, now)
	return err
}

// Announce implements orgdeletion.OrgStore.
func (s *Store) Announce(ctx context.Context, req orgdeletion.OrgRequest, now time.Time) error {
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		moved, err := moveOrgTx(ctx, tx, req.RequestID, orgdeletion.StepAnnounce, orgdeletion.StepCoolingOff, now, `, announced_at = $4`)
		if err != nil || !moved {
			return err
		}
		f, err := orgFactsTx(ctx, tx, req.OrgID, true)
		if err != nil || !f.Found {
			return err
		}
		if f.Status != "active" && f.Status != "suspended" {
			return nil // already pending deletion (an account deletion brought a request forward), or further
		}
		gen := f.Gen + 1
		in, err := hostapi.SetStateIntent(req.OrgID, pc.StatePendingDeletion, gen)
		if err != nil {
			return err
		}
		if err := setOrgStateTx(ctx, tx, req.OrgID, orgdeletion.StatusPendingDeletion, gen, now); err != nil {
			return err
		}
		return enqueueIntentsTx(ctx, tx, in)
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.Announce: %w", err)
	}
	return nil
}

// EndCoolingOff implements orgdeletion.OrgStore.
func (s *Store) EndCoolingOff(ctx context.Context, req orgdeletion.OrgRequest, now time.Time) (bool, error) {
	var moved bool
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE org_deletion_requests
			   SET step = 'cancel_billing', state = 'purging', updated_at = $2, next_attempt_at = $2,
			       step_entered_at = $2, attempts = 0, last_error_class = NULL
			 WHERE request_id = $1::uuid AND step = 'cooling_off' AND state = 'cooling_off'`, req.RequestID, now)
		moved = err == nil && tag.RowsAffected() == 1
		return err
	})
	if err != nil {
		return false, fmt.Errorf("cloudserver/store.EndCoolingOff: %w", err)
	}
	return moved, nil
}

// Fence implements orgdeletion.OrgStore.
func (s *Store) Fence(ctx context.Context, req orgdeletion.OrgRequest, in orgdeletion.FenceInput, now time.Time) error {
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		moved, err := moveOrgTx(ctx, tx, req.RequestID, orgdeletion.StepFence, orgdeletion.StepAwaitHost, now,
			`, state = 'purging', purge_gen = $5`, in.PurgeGen)
		if err != nil || !moved {
			return err
		}
		f, err := orgFactsTx(ctx, tx, req.OrgID, true)
		if err != nil || !f.Found {
			return err
		}
		if f.Status != orgdeletion.StatusPurged {
			if err := setOrgStateTx(ctx, tx, req.OrgID, orgdeletion.StatusPurging, in.PurgeGen, now); err != nil {
				return err
			}
		}
		if err := enqueueIntentsTx(ctx, tx, in.Intents...); err != nil {
			return err
		}
		// The org's sign-in client: no new code is issued for it, and the
		// unused ones go (oidcissuer refuses a disabled client).
		if _, err := tx.Exec(ctx, `UPDATE oidc_clients SET disabled_at = $2, updated_at = $2
			WHERE org_id = $1::uuid AND disabled_at IS NULL`, req.OrgID, now); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `DELETE FROM oidc_codes WHERE client_id = 'org:' || $1`, req.OrgID)
		return err
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.Fence: %w", err)
	}
	return nil
}

// IntentAck implements orgdeletion.OrgStore and orgdeletion.AccountStore.
func (s *Store) IntentAck(ctx context.Context, idempotencyKey string) (orgdeletion.HostAck, error) {
	var ack orgdeletion.HostAck
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var state, class string
		err := tx.QueryRow(ctx, `SELECT state, coalesce(last_error_class, '') FROM org_outbox WHERE idempotency_key = $1`,
			idempotencyKey).Scan(&state, &class)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		ack = orgdeletion.HostAck{Queued: true, Acked: state == "acked", Failed: state == "failed", Class: class}
		return nil
	})
	if err != nil {
		return orgdeletion.HostAck{}, fmt.Errorf("cloudserver/store.IntentAck: %w", err)
	}
	return ack, nil
}

// Finalize implements orgdeletion.OrgStore.
func (s *Store) Finalize(ctx context.Context, req orgdeletion.OrgRequest, purgedGen int64, now time.Time) error {
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		moved, err := moveOrgTx(ctx, tx, req.RequestID, orgdeletion.StepFinalize, orgdeletion.StepDone, now,
			`, state = 'done', done_at = $4`)
		if err != nil || !moved {
			return err
		}
		if err := setOrgStateTx(ctx, tx, req.OrgID, orgdeletion.StatusPurged, purgedGen, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM org_members WHERE org_id = $1::uuid`, req.OrgID); err != nil {
			return err
		}
		// FR-23: the (org, subject) rows the issuer recorded go with the org;
		// its sign-in client was disabled at the fence, so no new one comes.
		_, err = tx.Exec(ctx, `DELETE FROM org_sub_seen WHERE org_id = $1::uuid`, req.OrgID)
		return err
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.Finalize: %w", err)
	}
	return nil
}

// Restore implements orgdeletion.OrgStore.
func (s *Store) Restore(ctx context.Context, req orgdeletion.OrgRequest, intent func(gen int64) (hostapi.Intent, error), now time.Time) error {
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		moved, err := moveOrgTx(ctx, tx, req.RequestID, orgdeletion.StepRestore, orgdeletion.StepDone, now, ``)
		if err != nil || !moved {
			return err
		}
		f, err := orgFactsTx(ctx, tx, req.OrgID, true)
		if err != nil || !f.Found || f.Status != orgdeletion.StatusPendingDeletion {
			return err
		}
		gen := f.Gen + 1
		in, err := intent(gen)
		if err != nil {
			return err
		}
		if err := setOrgStateTx(ctx, tx, req.OrgID, "active", gen, now); err != nil {
			return err
		}
		return enqueueIntentsTx(ctx, tx, in)
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.Restore: %w", err)
	}
	return nil
}

// AdvanceOrg implements orgdeletion.OrgStore.
func (s *Store) AdvanceOrg(ctx context.Context, requestID string, from, to orgdeletion.Step, now time.Time) error {
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := moveOrgTx(ctx, tx, requestID, from, to, now, ``)
		return err
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.AdvanceOrg: %w", err)
	}
	return nil
}

// DeferOrg implements orgdeletion.OrgStore.
func (s *Store) DeferOrg(ctx context.Context, requestID string, step orgdeletion.Step, until time.Time, attempts int, class string) error {
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE org_deletion_requests
			   SET next_attempt_at = $3, attempts = $4, last_error_class = nullif($5, ''), updated_at = now()
			 WHERE request_id = $1::uuid AND step = $2`, requestID, string(step), until, attempts, class)
		return err
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.DeferOrg: %w", err)
	}
	return nil
}

// BlockOrg implements orgdeletion.OrgStore.
func (s *Store) BlockOrg(ctx context.Context, requestID string, step orgdeletion.Step, reason, class string, now time.Time) error {
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE org_deletion_requests
			   SET state = 'blocked', blocked_reason = $3, last_error_class = nullif($5, ''), updated_at = $4
			 WHERE request_id = $1::uuid AND step = $2`, requestID, string(step), reason, now, class)
		return err
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.BlockOrg: %w", err)
	}
	return nil
}

// stateForStep is the user word a resumed request takes back from its step.
func stateForStep(step string) string {
	switch orgdeletion.Step(step) {
	case orgdeletion.StepAnnounce, orgdeletion.StepCoolingOff:
		return orgdeletion.StateCoolingOff
	case orgdeletion.StepRestore:
		return orgdeletion.StateCanceled
	}
	return orgdeletion.StatePurging
}

// ResumeDeletion clears a block on the org request or account follow-up
// with this id (the operator's lever once the blocked reason is fixed: a
// billing seam wired, a parked host intent requeued). A resumed org request
// starts its step's clock again, so a host_purge_overdue block gets another
// HostPurgeGrace. With skipWait, a
// follow-up blocked at await_deactivate moves on to delete_identity: the
// operator's decision that the subject's remaining deactivations will not
// be acked (design 4.10 step 5). It reports whether it resumed anything.
func (s *Store) ResumeDeletion(ctx context.Context, requestID string, skipWait bool, now time.Time) (bool, error) {
	var resumed bool
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var step string
		err := tx.QueryRow(ctx, `SELECT step FROM org_deletion_requests WHERE request_id = $1::uuid AND state = 'blocked' FOR UPDATE`,
			requestID).Scan(&step)
		switch {
		case err == nil:
			_, err = tx.Exec(ctx, `UPDATE org_deletion_requests
				   SET state = $2, blocked_reason = NULL, attempts = 0, last_error_class = NULL,
				       next_attempt_at = $3, updated_at = $3, step_entered_at = $3
				 WHERE request_id = $1::uuid`, requestID, stateForStep(step), now)
			resumed = err == nil
			return err
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		extra := ``
		if skipWait {
			extra = `, step = CASE WHEN step = 'await_deactivate' THEN 'delete_identity' ELSE step END`
		}
		tag, err := tx.Exec(ctx, `UPDATE account_deletion_followups
			   SET state = 'running', blocked_reason = NULL, attempts = 0, last_error_class = NULL,
			       next_attempt_at = $2, updated_at = $2`+extra+`
			 WHERE request_id = $1::uuid AND state = 'blocked'`, requestID, now)
		resumed = err == nil && tag.RowsAffected() == 1
		return err
	})
	if isInvalidUUIDErr(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("cloudserver/store.ResumeDeletion: %w", err)
	}
	return resumed, nil
}

// --- the driver's account seam (sbci_worker) -----------------------------

// DueFollowups implements orgdeletion.AccountStore.
func (s *Store) DueFollowups(ctx context.Context, now time.Time, limit int) ([]orgdeletion.AccountFollowup, error) {
	var out []orgdeletion.AccountFollowup
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT request_id::text, account_id::text, subs, coalesce(personal_org_id::text, ''),
			       step, state, attempts, created_at
			  FROM account_deletion_followups
			 WHERE state = 'running' AND next_attempt_at <= $1
			 ORDER BY next_attempt_at
			 LIMIT $2`, now, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var f orgdeletion.AccountFollowup
			var step string
			if err := rows.Scan(&f.RequestID, &f.AccountID, &f.Subs, &f.PersonalOrgID, &step, &f.State, &f.Attempts, &f.CreatedAt); err != nil {
				return err
			}
			f.Step = orgdeletion.Step(step)
			out = append(out, f)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.DueFollowups: %w", err)
	}
	return out, nil
}

// VerifyFollowup implements orgdeletion.AccountStore (FR-12): cloud 0140's
// sbci_deletion_followup_check reads the row itself and checks it against
// deletion_requests and the personal org's kind and creator, so nothing the
// row's writer chose is trusted. "" when it checks out.
func (s *Store) VerifyFollowup(ctx context.Context, f orgdeletion.AccountFollowup) (string, error) {
	var verdict string
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT sbci_deletion_followup_check($1::uuid)`, f.RequestID).Scan(&verdict)
	})
	if isInvalidUUIDErr(err) {
		return "no_followup", nil
	}
	if err != nil {
		return "", fmt.Errorf("cloudserver/store.VerifyFollowup: %w", err)
	}
	if verdict == "ok" {
		return "", nil
	}
	return verdict, nil
}

// moveFollowupTx is the follow-up's compare-and-set.
func moveFollowupTx(ctx context.Context, tx pgx.Tx, requestID string, from, to orgdeletion.Step, now time.Time, extra string) (bool, error) {
	tag, err := tx.Exec(ctx, `UPDATE account_deletion_followups
		   SET step = $3, updated_at = $4, next_attempt_at = $4, attempts = 0, last_error_class = NULL`+extra+`
		 WHERE request_id = $1::uuid AND step = $2`, requestID, string(from), string(to), now)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// OpenPersonalOrgDeletion implements orgdeletion.AccountStore.
func (s *Store) OpenPersonalOrgDeletion(ctx context.Context, f orgdeletion.AccountFollowup, now time.Time) error {
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		moved, err := moveFollowupTx(ctx, tx, f.RequestID, orgdeletion.StepPersonalOrg, orgdeletion.StepMemberships, now, ``)
		if err != nil || !moved || f.PersonalOrgID == "" {
			return err
		}
		facts, err := orgFactsTx(ctx, tx, f.PersonalOrgID, true)
		if err != nil || !facts.Found || facts.Status == orgdeletion.StatusPurged {
			return err
		}
		var open, state string
		err = tx.QueryRow(ctx, `SELECT request_id::text, state FROM org_deletion_requests
			WHERE org_id = $1::uuid AND step <> 'done' FOR UPDATE`, f.PersonalOrgID).Scan(&open, &state)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			_, err = tx.Exec(ctx, `INSERT INTO org_deletion_requests
				       (org_id, requested_by, state, origin, step, purge_after, account_request_id, next_attempt_at)
				VALUES ($1::uuid, $2::uuid, 'cooling_off', 'account_deletion', 'announce', $3, $4::uuid, $3)`,
				f.PersonalOrgID, f.AccountID, now, f.RequestID)
			return err
		case err != nil:
			return err
		}
		// An open request is brought forward: no window, due now; a canceled
		// one (its org not yet restored) is reopened at announce, which leaves
		// a pending_deletion org as it is.
		_, err = tx.Exec(ctx, `UPDATE org_deletion_requests
			   SET purge_after = least(purge_after, $2), next_attempt_at = $2, updated_at = $2,
			       account_request_id = coalesce(account_request_id, $3::uuid),
			       state = CASE WHEN state = 'canceled' THEN 'cooling_off' ELSE state END,
			       step = CASE WHEN state = 'canceled' THEN 'announce' ELSE step END,
			       step_entered_at = CASE WHEN state = 'canceled' THEN $2 ELSE step_entered_at END,
			       canceled_at = CASE WHEN state = 'canceled' THEN NULL ELSE canceled_at END,
			       canceled_by = CASE WHEN state = 'canceled' THEN NULL ELSE canceled_by END
			 WHERE request_id = $1::uuid`, open, now, f.RequestID)
		return err
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.OpenPersonalOrgDeletion: %w", err)
	}
	return nil
}

// RemoveMemberships implements orgdeletion.AccountStore.
func (s *Store) RemoveMemberships(ctx context.Context, f orgdeletion.AccountFollowup, now time.Time) error {
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		moved, err := moveFollowupTx(ctx, tx, f.RequestID, orgdeletion.StepMemberships, orgdeletion.StepDeactivate, now, ``)
		if err != nil || !moved {
			return err
		}
		_, err = tx.Exec(ctx, `DELETE FROM org_members WHERE account_id = $1::uuid`, f.AccountID)
		return err
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.RemoveMemberships: %w", err)
	}
	return nil
}

// SubsSeen implements orgdeletion.AccountStore.
func (s *Store) SubsSeen(ctx context.Context, subs []string) ([]orgdeletion.SubSeen, error) {
	var out []orgdeletion.SubSeen
	if len(subs) == 0 {
		return nil, nil
	}
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT s.org_id::text, s.sub, o.kind
			  FROM org_sub_seen s JOIN orgs o ON o.org_id = s.org_id
			 WHERE s.sub = ANY($1)
			 ORDER BY s.org_id, s.sub`, subs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var x orgdeletion.SubSeen
			if err := rows.Scan(&x.OrgID, &x.Sub, &x.Kind); err != nil {
				return err
			}
			out = append(out, x)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.SubsSeen: %w", err)
	}
	return out, nil
}

// Deactivate implements orgdeletion.AccountStore.
func (s *Store) Deactivate(ctx context.Context, f orgdeletion.AccountFollowup, intents []hostapi.Intent, notices []string, now time.Time) error {
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		moved, err := moveFollowupTx(ctx, tx, f.RequestID, orgdeletion.StepDeactivate, orgdeletion.StepAwaitDeactivate, now, ``)
		if err != nil || !moved {
			return err
		}
		if err := enqueueIntentsTx(ctx, tx, intents...); err != nil {
			return err
		}
		for _, org := range notices {
			if _, err := tx.Exec(ctx, `INSERT INTO org_member_departure_notices (request_id, org_id, created_at)
				VALUES ($1::uuid, $2::uuid, $3) ON CONFLICT DO NOTHING`, f.RequestID, org, now); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.Deactivate: %w", err)
	}
	return nil
}

// FinishFollowup implements orgdeletion.AccountStore. The subjects are
// forgotten twice: the row's own list, and their org_sub_seen rows (FR-23;
// every deactivation they were needed for has been acked or waived).
func (s *Store) FinishFollowup(ctx context.Context, f orgdeletion.AccountFollowup, now time.Time) error {
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var subs []string
		err := tx.QueryRow(ctx, `SELECT subs FROM account_deletion_followups
			WHERE request_id = $1::uuid AND step = 'finish' FOR UPDATE`, f.RequestID).Scan(&subs)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // already finished, or elsewhere: the compare-and-set rule
		}
		if err != nil {
			return err
		}
		moved, err := moveFollowupTx(ctx, tx, f.RequestID, orgdeletion.StepFinish, orgdeletion.StepDone, now,
			`, state = 'done', done_at = $4, subs = '{}'`)
		if err != nil || !moved || len(subs) == 0 {
			return err
		}
		_, err = tx.Exec(ctx, `DELETE FROM org_sub_seen WHERE sub = ANY($1)`, subs)
		return err
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.FinishFollowup: %w", err)
	}
	return nil
}

// AdvanceFollowup implements orgdeletion.AccountStore.
func (s *Store) AdvanceFollowup(ctx context.Context, requestID string, from, to orgdeletion.Step, now time.Time) error {
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := moveFollowupTx(ctx, tx, requestID, from, to, now, ``)
		return err
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.AdvanceFollowup: %w", err)
	}
	return nil
}

// DeferFollowup implements orgdeletion.AccountStore.
func (s *Store) DeferFollowup(ctx context.Context, requestID string, step orgdeletion.Step, until time.Time, attempts int, class string) error {
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE account_deletion_followups
			   SET next_attempt_at = $3, attempts = $4, last_error_class = nullif($5, ''), updated_at = now()
			 WHERE request_id = $1::uuid AND step = $2`, requestID, string(step), until, attempts, class)
		return err
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.DeferFollowup: %w", err)
	}
	return nil
}

// BlockFollowup implements orgdeletion.AccountStore.
func (s *Store) BlockFollowup(ctx context.Context, requestID string, step orgdeletion.Step, reason, class string, now time.Time) error {
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE account_deletion_followups
			   SET state = 'blocked', blocked_reason = $3, last_error_class = nullif($5, ''), updated_at = $4
			 WHERE request_id = $1::uuid AND step = $2`, requestID, string(step), reason, now, class)
		return err
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.BlockFollowup: %w", err)
	}
	return nil
}

// --- the account deletion's org half (sbci_api, account context) ----------

// AccountDeletionBlockedError is a refused account deletion: memberships the
// account must settle first (orgdeletion.Precheck).
type AccountDeletionBlockedError struct {
	Blockers []orgdeletion.Blocker
}

// ErrAccountDeletionBlocked is the sentinel an *AccountDeletionBlockedError
// matches.
var ErrAccountDeletionBlocked = errors.New("cloudserver/store: the account deletion is blocked by its orgs")

func (e *AccountDeletionBlockedError) Error() string {
	return fmt.Sprintf("cloudserver/store: %d org(s) block the account deletion", len(e.Blockers))
}

// Unwrap makes errors.Is(err, ErrAccountDeletionBlocked) true.
func (e *AccountDeletionBlockedError) Unwrap() error { return ErrAccountDeletionBlocked }

// accountMembershipsTx reads the account's memberships with the facts the
// precheck needs, under the account's own RLS context. The owner and member
// counts are of LIVE accounts only (cloud 0140 sbci_org_live_member_counts):
// the membership of an account already deleted, which the worker removes
// later, no longer counts as another owner (FR-23).
func accountMembershipsTx(ctx context.Context, tx pgx.Tx, accountID string) ([]orgdeletion.Membership, error) {
	rows, err := tx.Query(ctx, `
		SELECT o.org_id::text, o.slug, o.display_name, o.kind, o.status, m.console_role, m.is_billing_owner,
		       coalesce(c.owners, 0), coalesce(c.members, 0)
		  FROM org_members m JOIN orgs o ON o.org_id = m.org_id
		  LEFT JOIN LATERAL sbci_org_live_member_counts(o.org_id) c ON true
		 WHERE m.account_id = $1::uuid
		 ORDER BY o.kind, o.slug`, accountID)
	if err != nil {
		return nil, fmt.Errorf("account memberships: %w", err)
	}
	defer rows.Close()
	var out []orgdeletion.Membership
	for rows.Next() {
		var m orgdeletion.Membership
		var owners, members int64
		if err := rows.Scan(&m.OrgID, &m.Slug, &m.DisplayName, &m.Kind, &m.Status, &m.Role, &m.BillingOwner, &owners, &members); err != nil {
			return nil, fmt.Errorf("account memberships: %w", err)
		}
		m.Owners, m.Members = int(owners), int(members)
		out = append(out, m)
	}
	return out, rows.Err()
}

// accountDeletionPlanTx is the precheck inside the caller's account
// transaction: the org memberships' plan plus the account's paid live orgs
// (the C2.front-door-5 A rule) as blockers.
func accountDeletionPlanTx(ctx context.Context, tx pgx.Tx, accountID string) (orgdeletion.AccountPlan, error) {
	ms, err := accountMembershipsTx(ctx, tx, accountID)
	if err != nil {
		return orgdeletion.AccountPlan{}, err
	}
	plan := orgdeletion.Precheck(ms)
	paid, err := paidLiveOrgsTx(ctx, tx, accountID)
	if err != nil {
		return orgdeletion.AccountPlan{}, err
	}
	var pays []orgdeletion.Blocker
	for _, o := range paid {
		pays = append(pays, orgdeletion.Blocker{Code: orgdeletion.BlockerPaysForLiveOrg, OrgID: o.OrgID, Slug: o.Slug, DisplayName: o.DisplayName})
	}
	plan.Blockers = append(pays, plan.Blockers...)
	return plan, nil
}

// AccountDeletionPlan is the console's precheck: what deleting accountID
// would do with its orgs, and what blocks it. The deletion re-checks inside
// its own transaction.
func (s *Store) AccountDeletionPlan(ctx context.Context, accountID string) (orgdeletion.AccountPlan, error) {
	var plan orgdeletion.AccountPlan
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		plan, err = accountDeletionPlanTx(ctx, tx, accountID)
		return err
	})
	if err != nil {
		return orgdeletion.AccountPlan{}, fmt.Errorf("cloudserver/store.AccountDeletionPlan: %w", err)
	}
	return plan, nil
}

// orgOwnersLockKey is the advisory lock key of one org's owner set (FR-23).
func orgOwnersLockKey(orgID string) string { return "sbci_org_owners:" + orgID }

// lockOwnedTeamOrgsTx takes the per-org owner lock of every team org the
// account owns, in org id order (no lock-order deadlock between two
// deletions), for the rest of the transaction. Two owners of one team
// deleting their accounts at once serialise here: the second reads the
// first's account as deleted and is refused as the sole owner (FR-23).
func lockOwnedTeamOrgsTx(ctx context.Context, tx pgx.Tx, ms []orgdeletion.Membership) error {
	var ids []string
	for _, m := range ms {
		if m.Kind == orgdeletion.KindTeam && m.Role == orgdeletion.RoleOwner {
			ids = append(ids, m.OrgID)
		}
	}
	slices.Sort(ids)
	for _, id := range ids {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, orgOwnersLockKey(id)); err != nil {
			return fmt.Errorf("org owners lock: %w", err)
		}
	}
	return nil
}

// refuseIfOrgsBlockTx returns an *AccountDeletionBlockedError when the
// account's memberships block its deletion (the paid-live rule is checked
// before, by refuseIfPaysForLiveOrg, with its own error). It locks the
// team orgs the account owns first and reads the memberships again under
// the locks.
func refuseIfOrgsBlockTx(ctx context.Context, tx pgx.Tx, accountID string) error {
	ms, err := accountMembershipsTx(ctx, tx, accountID)
	if err != nil {
		return err
	}
	if err := lockOwnedTeamOrgsTx(ctx, tx, ms); err != nil {
		return err
	}
	if ms, err = accountMembershipsTx(ctx, tx, accountID); err != nil {
		return err
	}
	if plan := orgdeletion.Precheck(ms); !plan.CanDelete() {
		return &AccountDeletionBlockedError{Blockers: plan.Blockers}
	}
	return nil
}

// recordAccountFollowupTx writes the account deletion's org-side follow-up in
// the deletion transaction, before the identity links are purged: the
// account's WorkOS subjects and its personal org. Idempotent on the request.
func recordAccountFollowupTx(ctx context.Context, tx pgx.Tx, accountID, requestID string, now time.Time) error {
	var subs []string
	rows, err := tx.Query(ctx, `SELECT subject FROM identity_links WHERE account_id = $1::uuid AND provider = 'workos' ORDER BY subject`, accountID)
	if err != nil {
		return fmt.Errorf("follow-up subjects: %w", err)
	}
	for rows.Next() {
		var sub string
		if err := rows.Scan(&sub); err != nil {
			rows.Close()
			return fmt.Errorf("follow-up subjects: %w", err)
		}
		subs = append(subs, sub)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("follow-up subjects: %w", err)
	}
	if subs == nil {
		subs = []string{}
	}
	var personal *string
	err = tx.QueryRow(ctx, `SELECT org_id::text FROM orgs WHERE created_by = $1::uuid AND kind = 'personal'`, accountID).Scan(&personal)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("follow-up personal org: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO account_deletion_followups
		       (request_id, account_id, subs, personal_org_id, created_at, updated_at, next_attempt_at)
		VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5, $5, $5)
		ON CONFLICT DO NOTHING`, requestID, accountID, subs, personal, now); err != nil {
		return fmt.Errorf("follow-up: %w", err)
	}
	return nil
}

// --- staff status ----------------------------------------------------------

// DeletionStatusRow is one deletion as the staff console shows it: ids,
// steps, times and enum classes only.
type DeletionStatusRow struct {
	Kind           string // "org" or "account"
	RequestID      string
	OrgID          string
	State          string
	Step           string
	Origin         string
	BlockedReason  string
	Attempts       int
	LastErrorClass string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	NextAttemptAt  time.Time
	PurgeAfter     *time.Time
	DoneAt         *time.Time
}

// ListDeletions returns the org deletions and account follow-ups, open ones
// first, newest first, at most limit of each (the staff status route; the
// staff login reads no subject).
func (s *Store) ListDeletions(ctx context.Context, limit int) ([]DeletionStatusRow, error) {
	if limit <= 0 {
		limit = 100
	}
	var out []DeletionStatusRow
	err := s.WithStaff(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			(SELECT 'org', request_id::text, org_id::text, state, step, origin, coalesce(blocked_reason, ''), attempts,
			        coalesce(last_error_class, ''), created_at, updated_at, next_attempt_at, purge_after, done_at
			   FROM org_deletion_requests
			  ORDER BY (step <> 'done') DESC, created_at DESC LIMIT $1)
			UNION ALL
			(SELECT 'account', request_id::text, coalesce(personal_org_id::text, ''), state, step, '', coalesce(blocked_reason, ''), attempts,
			        coalesce(last_error_class, ''), created_at, updated_at, next_attempt_at, NULL::timestamptz, done_at
			   FROM account_deletion_followups
			  ORDER BY (state <> 'done') DESC, created_at DESC LIMIT $1)`, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r DeletionStatusRow
			if err := rows.Scan(&r.Kind, &r.RequestID, &r.OrgID, &r.State, &r.Step, &r.Origin, &r.BlockedReason, &r.Attempts,
				&r.LastErrorClass, &r.CreatedAt, &r.UpdatedAt, &r.NextAttemptAt, &r.PurgeAfter, &r.DoneAt); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.ListDeletions: %w", err)
	}
	return out, nil
}

// operatorAccount is the requested_by of a request the operator's restore
// reconciliation opened (an opaque id that names no account).
const operatorAccount = "00000000-0000-0000-0000-000000000000"

// ReapplyOrgDeletionsFromJournal is the restore runbook's org step (plan 06
// 5.3.10 step 5, "after any PITR or dump restore, a reconciliation re-runs
// the purge for every journaled org before traffic opens"): for every org
// the deletion journal records as fenced, it makes sure the restored
// database drives that org to purged again. A request the restore put back
// before its fence (announce, cooling_off, cancel_billing, or canceled) is
// moved to fence with its window ended; an org with no request and no
// finished one gets a staff-origin request at fence (skipped when the
// restore predates the org itself). A finished deletion (done) and a request
// already at or past the fence are left alone. It reads no org row (the
// operator's role has no org policy) and is idempotent;
// the worker's driver does the rest. It returns how many orgs it re-armed.
func (s *Store) ReapplyOrgDeletionsFromJournal(ctx context.Context, now time.Time) (int, error) {
	if s.deletionJournal == nil {
		return 0, errors.New("cloudserver/store.ReapplyOrgDeletionsFromJournal: no journal configured")
	}
	records, err := s.deletionJournal.Records(ctx)
	if err != nil {
		return 0, fmt.Errorf("cloudserver/store.ReapplyOrgDeletionsFromJournal: %w", err)
	}
	n := 0
	for _, org := range deletionjournal.AcceptedOrgs(records) {
		var rearmed bool
		err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `UPDATE org_deletion_requests
				   SET state = 'purging', step = 'fence', purge_after = least(purge_after, $2), next_attempt_at = $2,
				       step_entered_at = $2,
				       blocked_reason = NULL, attempts = 0, last_error_class = NULL, canceled_at = NULL, canceled_by = NULL,
				       updated_at = $2
				 WHERE org_id = $1::uuid AND step IN ('announce', 'cooling_off', 'cancel_billing', 'restore')`, org, now)
			if err != nil {
				return err
			}
			if tag.RowsAffected() > 0 {
				rearmed = true
				return nil
			}
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM org_deletion_requests
				WHERE org_id = $1::uuid AND (step <> 'done' OR state = 'done'))`, org).Scan(&exists); err != nil {
				return err
			}
			if exists {
				return nil
			}
			tag, err = tx.Exec(ctx, `INSERT INTO org_deletion_requests
				       (org_id, requested_by, state, origin, step, purge_after, next_attempt_at)
				VALUES ($1::uuid, $2::uuid, 'purging', 'staff', 'fence', $3, $3)
				ON CONFLICT (org_id) WHERE step <> 'done' DO NOTHING`, org, operatorAccount, now)
			rearmed = err == nil && tag.RowsAffected() == 1
			return err
		})
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			continue // the restore predates the org itself: nothing to purge
		}
		if err != nil {
			return n, fmt.Errorf("cloudserver/store.ReapplyOrgDeletionsFromJournal: %s: %w", org, err)
		}
		if rearmed {
			n++
		}
	}
	return n, nil
}

// DeletionJournal returns the store's deletion journal (nil when none is
// configured), for the deletion driver, which appends the org records.
func (s *Store) DeletionJournal() deletionjournal.Journal { return s.deletionJournal }
