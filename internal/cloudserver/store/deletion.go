package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/deletionjournal"
)

// deletion.go brings account deletion to substantive COMPLETION (divergence
// remediation plan §3 W6d; closes E6). The prior skeleton fenced the account,
// tombstoned result text, revoked credentials and deleted a few tables but left
// the request 'processing' forever with most tenant tables still populated.
//
// W6d makes deletion a complete, FK-safe purge-or-pseudonymize in ONE
// transaction, flips the request to 'done', and — via an append-only journal
// OUTSIDE the Postgres restore domain (see SuppressFromJournal) — makes the
// deletion survivable across a point-in-time restore.
//
// DESIGN NOTE — FK-forced matrix refinement (surfaced by ground-truthing the FK
// graph, 2026-09-02; flagged for the grouped Sol review):
// the plan's W6d matrix classified analysis_results/result_revisions as
// "tombstone at deletion, PURGE 30 days later". But the enrichment cluster is
// FK-connected: result_revisions -> analysis_results -> analysis_jobs ->
// {evidence_objects, usage_reservations}; evidence_objects -> cloud_sessions ->
// cloud_projects. Tombstone-keeping analysis_results therefore PINS the whole
// cluster (analysis_jobs, evidence_objects, usage_reservations, cloud_sessions,
// cloud_projects) — none of them can be purged while a retained result row
// references them — so a partial "purge some, keep some" at deletion is not
// FK-implementable. The chosen resolution PURGES the entire enrichment cluster
// immediately at deletion, children-before-parents, in one transaction. This is
// strictly MORE privacy-protective than the tombstone-then-30d design (it
// removes the data sooner), it needs no fragile time-coupled sweep, and it loses
// no audit basis: the retained tables that carry a real legal/billing/consent
// basis (consent_receipts, consent_events, portal_consent_events,
// analysis_usage_ledger, security_audit_events, structural_grants,
// deletion_requests) are untouched by the purge. The 30d tombstone was "built
// reality + a hygiene TTL" (rev-4.1 F7), not a retention requirement, so
// subsuming it into an immediate purge is a faithful refinement. The plan matrix
// is updated to record this; the grouped Sol review ratifies it before deploy.

// DeletionRequest is the recorded request plus a summary of the actions taken.
type DeletionRequest struct {
	ID    string `json:"id"`
	State string `json:"state"`
	// Legacy summary counts kept on the API response shape.
	JobsCanceled   int `json:"jobs_canceled"`
	DevicesRevoked int `json:"devices_revoked"`
	TokensRevoked  int `json:"tokens_revoked"`
	// PurgedRows is the total tenant rows purged across the enrichment cluster +
	// credential + lifecycle tables (content-free; a count, never any text).
	PurgedRows int `json:"purged_rows"`
}

// deletionAccountTombstoneTTL is how long the pseudonymized account ROW is kept
// after 'done' before a later retention pass purges it outright (abuse/forensics
// basis, same clock as security_audit_events). The enrichment data is already
// gone at 'done'; this governs only the opaque tombstone row + retained audit.
const deletionAccountTombstoneTTL = 24 * 30 * 24 * time.Hour // ~24 months

// CreateDeletionRequest records and executes an account deletion (dev-auth
// body-reauth path). It fails closed if no deletion journal is configured — a
// deletion must never run without a durable, restore-surviving record.
func (s *Store) CreateDeletionRequest(ctx context.Context, accountID string, now time.Time) (DeletionRequest, error) {
	return s.runDeletion(ctx, accountID, now, nil)
}

// CreateDeletionRequestWithStepUp is the WorkOS-mode entry point: it consumes a
// one-use step-up authorization and runs the SAME deletion in the SAME
// transaction (atomic — a failed deletion rolls the authorization back
// unconsumed, and a consumed authorization can never drive a second deletion).
func (s *Store) CreateDeletionRequestWithStepUp(ctx context.Context, accountID, sessionID, authzID string, now time.Time) (DeletionRequest, error) {
	return s.runDeletion(ctx, accountID, now, &stepUp{sessionID: sessionID, authzID: authzID})
}

type stepUp struct {
	sessionID string
	authzID   string
}

// runDeletion is the shared driver. It writes the durable "accepted" journal
// record INSIDE the transaction, AFTER authorization is established (a step-up is
// consumed) but BEFORE the destructive purge — so:
//   - a REFUSED step-up (invalid binding) never reaches the journal write, so a
//     later restore can never re-delete an account whose deletion was refused;
//   - a persisted "accepted" record only ever corresponds to an AUTHORIZED
//     deletion, so re-applying it on restore is always correct, even if this
//     transaction later rolled back (the user authorized the deletion and would
//     have retried);
//   - if the journal write itself fails, the transaction rolls back — no
//     deletion commits without a durable, restore-surviving record (fail-closed).
//
// The informational "done" record is written after commit (best-effort;
// suppression rests on "accepted").
func (s *Store) runDeletion(ctx context.Context, accountID string, now time.Time, su *stepUp) (DeletionRequest, error) {
	if now.IsZero() {
		now = time.Now()
	}
	if s.deletionJournal == nil {
		return DeletionRequest{}, errors.New("cloudserver/store: deletion journal not configured (fail-closed)")
	}

	var req DeletionRequest
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		if su != nil {
			if e := consumeStepUpTx(ctx, tx, accountID, su.sessionID, StepUpActionDeletion, su.authzID, now); e != nil {
				return e // refused step-up: rolls back, no journal write
			}
		}
		// Authorized. Durable "accepted" record before the destructive work.
		if e := s.deletionJournal.Append(ctx, deletionjournal.Record{
			Event:     deletionjournal.EventAccepted,
			AccountID: accountID,
			At:        now,
		}); e != nil {
			return fmt.Errorf("journal accepted: %w", e)
		}
		var e error
		req, e = deletionCompleteTx(ctx, tx, accountID, now)
		return e
	})
	if err != nil {
		if errors.Is(err, ErrStepUpInvalid) {
			return DeletionRequest{}, ErrStepUpInvalid
		}
		return DeletionRequest{}, fmt.Errorf("cloudserver/store.CreateDeletionRequest: %w", err)
	}

	// Informational done record; suppression already rests on the accepted one.
	if e := s.deletionJournal.Append(ctx, deletionjournal.Record{
		Event:     deletionjournal.EventDone,
		AccountID: accountID,
		RequestID: req.ID,
		At:        now,
	}); e != nil {
		return req, fmt.Errorf("cloudserver/store: deletion done but journal done-record failed: %w", e)
	}
	return req, nil
}

// deletionCompleteTx is the complete, FK-safe deletion inside the caller's tenant
// transaction. Every DELETE is account-scoped and RLS-bounded (SET LOCAL ROLE +
// tenant GUC), so it can only ever remove THIS account's rows. Order is
// children-before-parents so every NO-ACTION foreign key holds (see the design
// note above for the FK graph).
func deletionCompleteTx(ctx context.Context, tx pgx.Tx, accountID string, now time.Time) (DeletionRequest, error) {
	var req DeletionRequest

	// Fence + record (state starts 'processing'; flipped to 'done' at the end).
	if _, e := tx.Exec(ctx,
		`UPDATE accounts SET status = 'closed', updated_at = now()
		  WHERE account_id = $1::uuid AND status NOT IN ('closed','deleted')`,
		accountID); e != nil {
		return DeletionRequest{}, fmt.Errorf("fence account: %w", e)
	}
	if e := tx.QueryRow(ctx,
		`INSERT INTO deletion_requests (account_id, scope, state)
		 VALUES ($1::uuid, 'account', 'processing') RETURNING id::text, state`,
		accountID).Scan(&req.ID, &req.State); e != nil {
		return DeletionRequest{}, fmt.Errorf("record request: %w", e)
	}

	// Cancel non-terminal jobs first: releases reservations and deletes their
	// in-flight evidence. Must precede the analysis_jobs purge below.
	canceled, e := cancelNonTerminalJobsTx(ctx, tx, accountID, now)
	if e != nil {
		return DeletionRequest{}, fmt.Errorf("cancel jobs: %w", e)
	}
	req.JobsCanceled = canceled

	// Count devices + tokens before purging them (the summary counts).
	if e := tx.QueryRow(ctx,
		`SELECT count(*) FROM device_registrations WHERE account_id = $1::uuid`,
		accountID).Scan(&req.DevicesRevoked); e != nil {
		return DeletionRequest{}, fmt.Errorf("count devices: %w", e)
	}
	if e := tx.QueryRow(ctx,
		`SELECT count(*) FROM api_tokens WHERE account_id = $1::uuid`,
		accountID).Scan(&req.TokensRevoked); e != nil {
		return DeletionRequest{}, fmt.Errorf("count tokens: %w", e)
	}

	// PURGE order (children before parents). Each entry returns its row count so
	// the total is honest and the FK order is explicit and testable.
	purges := []struct {
		what string
		sql  string
	}{
		// Export artifacts (an assembled export is itself account data — plan §3
		// W6d "Export/deletion ordering": the deletion pass deletes any export
		// already assembled before the request). Independent of the FK cluster
		// (references only accounts), so order-free.
		{"export_artifacts", `DELETE FROM export_artifacts WHERE account_id = $1::uuid`},
		// Community contributions (W5). Tenant-owned; references only accounts +
		// the community_metrics registry (both NO ACTION), so it is independent of
		// the FK cluster and order-free. Deletion removes every contribution the
		// account made — the plan's opt-out/deletion linkage (§3 W5, R3 24h
		// removal); the published band snapshots recompute without them.
		{"leaderboard_contributions", `DELETE FROM leaderboard_contributions WHERE account_id = $1::uuid`},
		// Enrichment cluster, children first.
		{"result_revisions", `DELETE FROM result_revisions WHERE account_id = $1::uuid`},
		{"analysis_results", `DELETE FROM analysis_results WHERE account_id = $1::uuid`},
		{"analysis_jobs", `DELETE FROM analysis_jobs WHERE account_id = $1::uuid`},
		{"evidence_objects", `DELETE FROM evidence_objects WHERE account_id = $1::uuid`},
		{"evidence_blobs", `DELETE FROM evidence_blobs WHERE account_id = $1::uuid`},
		{"usage_reservations", `DELETE FROM usage_reservations WHERE account_id = $1::uuid`},
		{"usage_cycles", `DELETE FROM usage_cycles WHERE account_id = $1::uuid`},
		{"cloud_sessions", `DELETE FROM cloud_sessions WHERE account_id = $1::uuid`},
		{"cloud_projects", `DELETE FROM cloud_projects WHERE account_id = $1::uuid`},
		// Structural rail (structural_snapshots references device_registrations,
		// so it must precede the device purge below).
		{"structural_account_days", `DELETE FROM structural_account_days WHERE account_id = $1::uuid`},
		{"structural_snapshots", `DELETE FROM structural_snapshots WHERE account_id = $1::uuid`},
		// Credentials (api_tokens references device_registrations).
		{"api_tokens", `DELETE FROM api_tokens WHERE account_id = $1::uuid`},
		{"device_registrations", `DELETE FROM device_registrations WHERE account_id = $1::uuid`},
		{"browser_sessions", `DELETE FROM browser_sessions WHERE account_id = $1::uuid`},
		{"pop_replay", `DELETE FROM pop_replay WHERE account_id = $1::uuid`},
		{"step_up_authorizations", `DELETE FROM step_up_authorizations WHERE account_id = $1::uuid`},
		// Plans / entitlements / portal preferences / billing linkage.
		// paddle_subscriptions references only accounts (NO ACTION), independent of
		// the FK cluster; the Paddle-side billing lifecycle is not the node's concern.
		{"paddle_subscriptions", `DELETE FROM paddle_subscriptions WHERE account_id = $1::uuid`},
		// checkout_intents (migration 0030) is the account's ephemeral pre-checkout
		// state: a server-minted, single-use, TTL'd nonce hash bound to THIS
		// account. Account-scoped tenant data, so it is purged here explicitly —
		// its ON DELETE CASCADE only fires when the 24-month sweep finally drops
		// the pseudonymized account row, which is far too late for a deletion.
		// References only accounts (SYSTEM table, no RLS), so it is order-free.
		{"checkout_intents", `DELETE FROM checkout_intents WHERE account_id = $1::uuid`},
		{"entitlements", `DELETE FROM entitlements WHERE account_id = $1::uuid`},
		{"account_plans", `DELETE FROM account_plans WHERE account_id = $1::uuid`},
		{"portal_consent_choices", `DELETE FROM portal_consent_choices WHERE account_id = $1::uuid`},
		// The display-only profile row (migration 0033: the email + name the
		// portal top bar renders). Purged explicitly here rather than left to its
		// ON DELETE CASCADE, which would only fire when the 24-month sweep drops
		// the pseudonymized account row — 24 months too late for the one row that
		// holds a plain-text email address.
		{"account_profiles", `DELETE FROM account_profiles WHERE account_id = $1::uuid`},
		// Identity last of the purges — the subject store, gone with the profile
		// row above, leaves nothing that names the human behind the account.
		{"identity_links", `DELETE FROM identity_links WHERE account_id = $1::uuid`},
	}
	for _, p := range purges {
		ct, e := tx.Exec(ctx, p.sql, accountID)
		if e != nil {
			return DeletionRequest{}, fmt.Errorf("purge %s: %w", p.what, e)
		}
		req.PurgedRows += int(ct.RowsAffected())
	}

	// RETAIN (audit / legal / billing basis) — untouched except structural_grants,
	// which is REVOKED (the registration row survives as the consent-registration
	// fact, like consent_receipts, but authorizes no further upload):
	//   consent_receipts, consent_events, portal_consent_events,
	//   analysis_usage_ledger, security_audit_events, deletion_requests.
	if _, e := tx.Exec(ctx,
		`UPDATE structural_grants SET revoked_at = $2, updated_at = $2
		  WHERE account_id = $1::uuid AND revoked_at IS NULL`,
		accountID, now); e != nil {
		return DeletionRequest{}, fmt.Errorf("revoke structural grants: %w", e)
	}
	// community_grants is RETAINED-then-revoked on the same basis (the consent-
	// registration fact survives, authorizes no further contribution); the
	// 24-month retention sweep ages the revoked row out (migration 0026).
	if _, e := tx.Exec(ctx,
		`UPDATE community_grants SET revoked_at = $2, updated_at = $2
		  WHERE account_id = $1::uuid AND revoked_at IS NULL`,
		accountID, now); e != nil {
		return DeletionRequest{}, fmt.Errorf("revoke community grants: %w", e)
	}

	// Pseudonymize the account: keep the opaque UUID row as an irreversible
	// tombstone. status='deleted', deletion clock recorded, consent_generation
	// nulled to the reserved non-authorizing state (belt-and-suspenders behind
	// the status gate that already refuses non-'active' auth).
	if _, e := tx.Exec(ctx,
		`UPDATE accounts
		    SET status = 'deleted', consent_generation = NULL,
		        deleted_at = $2, purge_after = $3, updated_at = $2
		  WHERE account_id = $1::uuid`,
		accountID, now, now.Add(deletionAccountTombstoneTTL)); e != nil {
		return DeletionRequest{}, fmt.Errorf("pseudonymize account: %w", e)
	}

	// Flip the request to 'done' — reached only after every purge above committed
	// in this same transaction (all-or-nothing).
	if _, e := tx.Exec(ctx,
		`UPDATE deletion_requests SET state = 'done', completed_at = $2, detail = $3::jsonb
		  WHERE id = $1::uuid`,
		req.ID, now, fmt.Sprintf(`{"purged_rows":%d,"jobs_canceled":%d}`, req.PurgedRows, req.JobsCanceled)); e != nil {
		return DeletionRequest{}, fmt.Errorf("finalize request: %w", e)
	}
	req.State = "done"
	return req, nil
}

// SuppressFromJournal re-applies deletion to every account named in the
// deletion journal that is NOT currently tombstoned — the restore-runbook step
// that suppresses accounts a point-in-time restore resurrected. It is idempotent
// (an already-'deleted' account is skipped) and must run BEFORE the restored
// service reopens. Returns the number of accounts re-suppressed.
func (s *Store) SuppressFromJournal(ctx context.Context, now time.Time) (int, error) {
	if s.deletionJournal == nil {
		return 0, errors.New("cloudserver/store.SuppressFromJournal: no journal configured")
	}
	records, err := s.deletionJournal.Records(ctx)
	if err != nil {
		return 0, fmt.Errorf("cloudserver/store.SuppressFromJournal: %w", err)
	}
	suppressed := 0
	for _, accountID := range deletionjournal.AcceptedAccounts(records) {
		// Read current status under the tenant context.
		var status string
		var exists bool
		err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
			e := tx.QueryRow(ctx,
				`SELECT status FROM accounts WHERE account_id = $1::uuid`, accountID).Scan(&status)
			if errors.Is(e, pgx.ErrNoRows) {
				return nil // account row gone entirely — nothing to suppress
			}
			if e != nil {
				return e
			}
			exists = true
			return nil
		})
		if err != nil {
			return suppressed, fmt.Errorf("cloudserver/store.SuppressFromJournal: read %s: %w", accountID, err)
		}
		if !exists || status == "deleted" {
			continue // already gone or already tombstoned — idempotent skip
		}
		// Resurrected by the restore: re-run the complete deletion.
		if err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
			_, e := deletionCompleteTx(ctx, tx, accountID, now)
			return e
		}); err != nil {
			return suppressed, fmt.Errorf("cloudserver/store.SuppressFromJournal: re-delete %s: %w", accountID, err)
		}
		suppressed++
	}
	return suppressed, nil
}
