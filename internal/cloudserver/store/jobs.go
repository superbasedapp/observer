package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// Job terminal-reason constants (park/fail causes surfaced to the client).
const (
	ReasonProviderPolicyUnverified = "provider_policy_unverified"
	ReasonEvidenceExpired          = "evidence_expired"
	ReasonKillSwitched             = "kill_switched"
	ReasonReconfirmationRequired   = "reconfirmation_required"
	ReasonConsentRevoked           = "consent_revoked"
	ReasonEntitlementRevoked       = "entitlement_revoked"
	ReasonCanceled                 = "canceled"
	// ReasonDialectUnverified parks a job whose route selects the
	// responses_store_false dialect without a live operator verification record
	// (plan §2.3 — the dialect stays dark).
	ReasonDialectUnverified = "dialect_unverified"
	// ReasonProviderInvalidOutput fails a job whose provider produced invalid
	// output through the whole retry budget (plan §6 CI-P4).
	ReasonProviderInvalidOutput = "provider_invalid_output"
	// ReasonPersistenceViolation fails a job immediately when a
	// responses_store_false response indicated persistence (plan §2.3).
	ReasonPersistenceViolation = "persistence_violation"
	// ReasonExecutorMissing fails a job whose feature has no wired Executor in
	// the worker's feature -> Executor table (W5): a misconfigured worker
	// (e.g. project_digest jobs leased by a build that never wired
	// DigestExecutor) fails the job terminally rather than silently declining
	// forever or fabricating a result.
	ReasonExecutorMissing = "executor_missing"
)

// FeatureProjectDigest is the weekly per-project digest job kind (W5). Unlike
// FeatureSessionEnrichment it needs no per-account entitlements row — its
// entitlement is the resolved plan's digest_weekly flag alone (see
// reserveDigestAllowanceTx).
const FeatureProjectDigest = "project_digest"

// Result-kind discriminators (analysis_results.kind, migration 0037). Mirrored
// as plain string constants (not imported) from cloudcontract's identical
// values — the store package deliberately never imports cloudcontract
// (CLAUDE.md #1), so the two sides agree on the literal only.
const (
	// ResultKindSessionEnrichment is the default kind for every pre-existing
	// and every ordinary enrichment result.
	ResultKindSessionEnrichment = "session_enrichment"
	// ResultKindProjectDigest marks a weekly project-digest result row.
	ResultKindProjectDigest = "project_digest"
)

// SubmitJobInput is everything the API has resolved for one enrichment job. The
// canonical key + resolved route/prompt versions are computed by the API from
// the verified account (never a body field), the upload digest, and the route
// registry (Sol SC10).
type SubmitJobInput struct {
	AccountID      string
	CloudProjectID string
	CloudSessionID string
	Tool           string
	ModelFamily    string
	// Metrics is the content-free structural snapshot captured on
	// cloud_sessions at submit time (migration 0037, W5): the envelope's
	// MetricsBlock/Outcomes/ActivityMix, marshaled JSON, no excerpts/paths/
	// action targets. Empty ⇒ the stored snapshot (if any) is left unchanged.
	Metrics           []byte
	Feature           string
	RouteID           string
	RouteVersion      int64
	PromptVersion     int64
	CanonicalKey      string
	ClientIdemKey     string
	ConsentGeneration int64
	ConsentReceiptID  string // "" ⇒ NULL
	UploadDigest      string
	ContentDigest     string
	BlobRef           string
	SizeBytes         int64
	// EvidenceBytes is the exact serialized envelope the node uploaded. It is
	// encrypted and persisted to the blob store IN THE SAME transaction as the
	// evidence-object + job insert (plan §6 CI-P4: job submission persists
	// encrypted bytes atomically). Empty ⇒ no bytes stored (legacy/test path).
	EvidenceBytes []byte
	Now           time.Time
}

// JobSubmission is the outcome of SubmitJob.
type JobSubmission struct {
	JobID         string
	State         string
	Existing      bool // true ⇒ idempotent hit; no reservation was consumed
	ReservationID string
}

// errJobRace is an internal sentinel: an ON CONFLICT DO NOTHING found the
// canonical key already present (a concurrent identical submit won). The
// transaction is rolled back (discarding this call's reservation + evidence)
// and the existing job is returned.
var errJobRace = errors.New("cloudserver/store: job canonical key race")

// ErrAccountClosed is returned by SubmitJob when the account is not active
// (suspended, closed, or fenced for deletion). The submit is refused inside the
// transaction, serialized against the deletion fence via a FOR UPDATE lock on
// the accounts row (FE4), so no in-flight upload can store a blob that would
// survive account deletion.
var ErrAccountClosed = errors.New("cloudserver/store: account is not active")

// SubmitJob is idempotent by canonical job key (Sol SC10): the same key returns
// the same job WITHOUT consuming a second user unit; a different upload
// digest/route/prompt produces a different key and a new job. It makes the
// reservation, evidence-object write, and job insert atomic in one transaction
// so a conflict or failure leaks nothing.
func (s *Store) SubmitJob(ctx context.Context, in SubmitJobInput) (JobSubmission, error) {
	// Fast path: already-created identical job ⇒ no reservation, no evidence.
	if existing, err := s.jobByCanonicalKey(ctx, in.AccountID, in.CanonicalKey); err == nil {
		return existing, nil
	} else if !errors.Is(err, ErrNotFound) {
		return JobSubmission{}, err
	}

	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}

	var out JobSubmission
	err := s.WithAccount(ctx, in.AccountID, func(ctx context.Context, tx pgx.Tx) error {
		// FE4 fence: lock the accounts row and refuse a non-active account. This
		// serializes against the deletion fence (which UPDATEs accounts.status),
		// so a submit either commits its blob before the fence (purged by the
		// deletion transaction) or aborts here — never leaving surviving evidence.
		var status string
		if e := tx.QueryRow(ctx,
			`SELECT status FROM accounts WHERE account_id = $1::uuid FOR UPDATE`,
			in.AccountID).Scan(&status); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return ErrAccountClosed
			}
			return fmt.Errorf("lock account: %w", e)
		}
		if status != "active" {
			return ErrAccountClosed
		}
		projectPK, e := ensureProjectTx(ctx, tx, in.AccountID, in.CloudProjectID)
		if e != nil {
			return e
		}
		sessionPK, e := ensureSessionTx(ctx, tx, in.AccountID, projectPK, in.CloudSessionID, in.Tool, in.ModelFamily, in.Metrics)
		if e != nil {
			return e
		}
		reservationID, e := reserveAllowanceTx(ctx, tx, in.AccountID, in.Feature, now)
		if e != nil {
			return e
		}
		evidencePK, e := createEvidenceTx(ctx, tx, in.AccountID, sessionPK, in.BlobRef, in.UploadDigest, in.ContentDigest, in.SizeBytes, now)
		if e != nil {
			return e
		}
		// Persist the encrypted evidence BYTES atomically with the object + job
		// (plan §6 CI-P4). The worker Gets them under the execution lease.
		if len(in.EvidenceBytes) > 0 {
			if e := putEvidenceBlobTx(ctx, tx, s.enc, in.AccountID, in.BlobRef, in.EvidenceBytes, now); e != nil {
				return e
			}
		}

		var jobID string
		e = tx.QueryRow(ctx,
			`INSERT INTO analysis_jobs
			   (account_id, session_pk, evidence_pk, feature, route_id, route_version, prompt_version,
			    canonical_job_key, client_idempotency_key, consent_generation, consent_receipt_id,
			    upload_digest, state, reservation_id, available_at)
			 VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, $8, $9, $10, $11::uuid, $12, 'queued', $13::uuid, $14)
			 ON CONFLICT (account_id, canonical_job_key) DO NOTHING
			 RETURNING id::text`,
			in.AccountID, sessionPK, evidencePK, in.Feature, in.RouteID, in.RouteVersion, in.PromptVersion,
			in.CanonicalKey, nullString(in.ClientIdemKey), in.ConsentGeneration, nullString(in.ConsentReceiptID),
			in.UploadDigest, reservationID, now).Scan(&jobID)
		if errors.Is(e, pgx.ErrNoRows) {
			// Lost the race: roll back (discards reservation + evidence).
			return errJobRace
		}
		if e != nil {
			return fmt.Errorf("insert job: %w", e)
		}
		// Bind the reservation to the job for the ledger/audit trail.
		if _, e := tx.Exec(ctx,
			`UPDATE usage_reservations SET job_id = $3::uuid WHERE account_id = $1::uuid AND id = $2::uuid`,
			in.AccountID, reservationID, jobID); e != nil {
			return fmt.Errorf("bind reservation: %w", e)
		}
		out = JobSubmission{JobID: jobID, State: "queued", ReservationID: reservationID}
		return nil
	})
	if errors.Is(err, errJobRace) {
		return s.jobByCanonicalKey(ctx, in.AccountID, in.CanonicalKey)
	}
	if err != nil {
		return JobSubmission{}, err
	}
	return out, nil
}

func (s *Store) jobByCanonicalKey(ctx context.Context, accountID, key string) (JobSubmission, error) {
	var out JobSubmission
	out.Existing = true
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		var reservationID *string
		e := tx.QueryRow(ctx,
			`SELECT id::text, state, reservation_id::text FROM analysis_jobs
			  WHERE account_id = $1::uuid AND canonical_job_key = $2`,
			accountID, key).Scan(&out.JobID, &out.State, &reservationID)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return e
		}
		if reservationID != nil {
			out.ReservationID = *reservationID
		}
		return nil
	})
	if err != nil {
		return JobSubmission{}, err
	}
	return out, nil
}

// Job is the GET /v1/intelligence/jobs/{id} view.
type Job struct {
	ID             string    `json:"id"`
	State          string    `json:"state"`
	TerminalReason string    `json:"terminal_reason,omitempty"`
	Feature        string    `json:"feature"`
	Attempts       int       `json:"attempts"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// GetJob loads one job (tenant-scoped).
func (s *Store) GetJob(ctx context.Context, accountID, jobID string) (Job, error) {
	var j Job
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		var reason *string
		e := tx.QueryRow(ctx,
			`SELECT id::text, state, terminal_reason, feature, attempts, created_at, updated_at
			   FROM analysis_jobs WHERE account_id = $1::uuid AND id = $2::uuid`,
			accountID, jobID).Scan(&j.ID, &j.State, &reason, &j.Feature, &j.Attempts, &j.CreatedAt, &j.UpdatedAt)
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if e != nil {
			return e
		}
		if reason != nil {
			j.TerminalReason = *reason
		}
		return nil
	})
	return j, err
}

// LeasedJob is what the SECURITY DEFINER lease function returns (the worker's
// entry point). AccountID is authoritative; the worker opens a tenant tx with it.
type LeasedJob struct {
	JobID             string
	AccountID         string
	EvidencePK        string
	Feature           string
	RouteID           string
	RouteVersion      int64
	PromptVersion     int64
	ConsentGeneration int64
	ConsentReceiptID  string
	ReservationID     string
	Attempts          int
	// LeaseWorker is the worker id that holds this lease. It is NOT returned by
	// the lease function; the worker stamps it (it leased with its own id) so the
	// completion CAS (FA8) can require the lease owner to be unchanged.
	LeaseWorker string
	// LeaseGeneration is the durable per-lease counter the dequeue primitive
	// increments on EVERY lease (fresh or expiry-reclaim). The completion CAS
	// requires it to be unchanged (FA8), so a stale attempt whose job was
	// re-leased — even by the SAME worker id, with a refreshed expiry — cannot
	// store its result: the re-lease bumped the generation.
	LeaseGeneration int64
}

// ParkJob transitions a leased/running/queued job to a terminal PARKED state
// with a reason, releasing the reservation (refunding the user unit — no result
// was produced this phase) and deleting the temporary evidence early. Atomic.
func (s *Store) ParkJob(ctx context.Context, accountID, jobID, reason string, now time.Time) error {
	return s.terminate(ctx, accountID, jobID, "parked", reason, now)
}

// CancelJob is a park with reason=canceled (used by deletion requests to stop
// queued/leased jobs). Atomic.
func (s *Store) CancelJob(ctx context.Context, accountID, jobID string, now time.Time) error {
	return s.terminate(ctx, accountID, jobID, "canceled", ReasonCanceled, now)
}

// FailJob transitions a job to a terminal FAILED state with a reason,
// refunding the reservation (no accepted result was produced) and deleting the
// temporary evidence + bytes early. Used when the provider produced invalid
// output after the retry budget is exhausted (plan §6 CI-P4). Atomic.
func (s *Store) FailJob(ctx context.Context, accountID, jobID, reason string, now time.Time) error {
	return s.terminate(ctx, accountID, jobID, "failed", reason, now)
}

func (s *Store) terminate(ctx context.Context, accountID, jobID, state, reason string, now time.Time) error {
	if now.IsZero() {
		now = time.Now()
	}
	return s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		return terminateJobTx(ctx, tx, accountID, jobID, state, reason, now)
	})
}

// terminateJobTx is the tx-capable core of terminate: it flips one non-terminal
// job to a terminal state, releases its reservation, and deletes its evidence —
// all on the caller's transaction. CreateDeletionRequest calls it in a loop so
// job cancellation joins the single atomic deletion transaction (FE4). Returns
// ErrNotFound when the job is already terminal or not this account's.
func terminateJobTx(ctx context.Context, tx pgx.Tx, accountID, jobID, state, reason string, now time.Time) error {
	var evidencePK string
	var reservationID *string
	e := tx.QueryRow(ctx,
		`UPDATE analysis_jobs
		    SET state = $3, terminal_reason = $4, lease_worker = NULL, lease_expires_at = NULL, updated_at = $5
		  WHERE account_id = $1::uuid AND id = $2::uuid
		    AND state IN ('queued','leased','running')
		  RETURNING evidence_pk::text, reservation_id::text`,
		accountID, jobID, state, reason, now).Scan(&evidencePK, &reservationID)
	if errors.Is(e, pgx.ErrNoRows) {
		return ErrNotFound // already terminal, or not this account's
	}
	if e != nil {
		return fmt.Errorf("terminate job: %w", e)
	}
	if reservationID != nil {
		if e := finalizeReservationTx(ctx, tx, accountID, *reservationID, "released", true); e != nil {
			return e
		}
	}
	return deleteEvidenceForJobTx(ctx, tx, accountID, evidencePK, now)
}

// cancelNonTerminalJobsTx cancels every queued/leased/running job for the account
// on the caller's transaction and returns the count. It is the tx-capable form of
// CancelQueuedJobs, used by CreateDeletionRequest so cancellation is part of the
// single atomic deletion transaction (FE4).
func cancelNonTerminalJobsTx(ctx context.Context, tx pgx.Tx, accountID string, now time.Time) (int, error) {
	rows, err := tx.Query(ctx,
		`SELECT id::text FROM analysis_jobs
		  WHERE account_id = $1::uuid AND state IN ('queued','leased','running')`,
		accountID)
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if e := rows.Scan(&id); e != nil {
			rows.Close()
			return 0, e
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, id := range ids {
		if e := terminateJobTx(ctx, tx, accountID, id, "canceled", ReasonCanceled, now); e != nil && !errors.Is(e, ErrNotFound) {
			return 0, e
		}
	}
	return len(ids), nil
}

// deleteEvidenceForJobTx marks the evidence object deleted AND deletes its
// encrypted bytes, inside an existing tenant transaction. Used by every
// terminal transition so no evidence outlives its job.
func deleteEvidenceForJobTx(ctx context.Context, tx pgx.Tx, accountID, evidencePK string, now time.Time) error {
	var blobRef string
	e := tx.QueryRow(ctx,
		`SELECT blob_ref FROM evidence_objects WHERE account_id = $1::uuid AND id = $2::uuid`,
		accountID, evidencePK).Scan(&blobRef)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return fmt.Errorf("read evidence blob_ref: %w", e)
	}
	if e := markEvidenceDeletedTx(ctx, tx, accountID, evidencePK, now); e != nil {
		return e
	}
	return deleteEvidenceBlobTx(ctx, tx, accountID, blobRef)
}

// CancelQueuedJobs cancels every non-terminal job for the account (deletion
// skeleton). Returns how many were canceled.
func (s *Store) CancelQueuedJobs(ctx context.Context, accountID string, now time.Time) (int, error) {
	var ids []string
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT id::text FROM analysis_jobs
			  WHERE account_id = $1::uuid AND state IN ('queued','leased','running')`,
			accountID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if e := rows.Scan(&id); e != nil {
				return e
			}
			ids = append(ids, id)
		}
		return rows.Err()
	})
	if err != nil {
		return 0, err
	}
	for _, id := range ids {
		if e := s.CancelJob(ctx, accountID, id, now); e != nil && !errors.Is(e, ErrNotFound) {
			return 0, e
		}
	}
	return len(ids), nil
}

// --- Project digest (W5) ---------------------------------------------------

// SubmitDigestJobInput is everything the digest scheduler has resolved for one
// project-digest job. Unlike SubmitJobInput there is no CloudSessionID (a
// digest covers a whole project, not one session) and no ConsentReceiptID (a
// digest is a server-side rollup over data the node already sent under its own
// per-session consent — it asks the node for nothing new).
type SubmitDigestJobInput struct {
	AccountID      string
	CloudProjectID string
	// PeriodStart / PeriodEnd are the digest's ISO week bounds ("YYYY-MM-DD").
	PeriodStart   string
	PeriodEnd     string
	RouteID       string
	RouteVersion  int64
	PromptVersion int64
	// EvidenceBytes is the exact serialized cloudcontract.DigestEvidence the
	// scheduler built (server-internal; never a node upload). Persisted
	// (encrypted) atomically with the evidence-object + job insert, exactly
	// like SubmitJob.
	EvidenceBytes []byte
	BlobRef       string
	UploadDigest  string
	ContentDigest string
	SizeBytes     int64
	Now           time.Time
}

// digestCanonicalKey derives the canonical idempotency key for one project
// digest: account + project + period + resolved route/prompt versions. A
// re-run of the scheduler for the SAME (account, project, period) — the
// ordinary idempotent case — always recomputes this same key, so SubmitJob's
// canonical-key fast path (jobByCanonicalKey) returns the existing job without
// consuming a second reservation.
func digestCanonicalKey(accountID, cloudProjectID, periodStart, periodEnd string, routeVer, promptVer int64) string {
	h := sha256.New()
	for _, part := range []string{accountID, cloudProjectID, periodStart, periodEnd} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	h.Write([]byte(strconv.FormatInt(routeVer, 10)))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(promptVer, 10)))
	return "cjk:digest:" + hex.EncodeToString(h.Sum(nil))
}

// SubmitDigestJob is the server-internal sibling of SubmitJob for the
// project_digest feature (W5): idempotent by canonical key, reserves one
// FeatureProjectDigest allowance unit against the account's CURRENT plan
// (reserveDigestAllowanceTx — never an entitlements-row check), stores the
// evidence bytes with the standard immutable 1h TTL, and enqueues a job with
// session_pk NULL (a digest covers a project, not one session).
func (s *Store) SubmitDigestJob(ctx context.Context, in SubmitDigestJobInput) (JobSubmission, error) {
	canonical := digestCanonicalKey(in.AccountID, in.CloudProjectID, in.PeriodStart, in.PeriodEnd, in.RouteVersion, in.PromptVersion)

	// Fast path: already-created identical digest job ⇒ no reservation, no
	// evidence (mirrors SubmitJob).
	if existing, err := s.jobByCanonicalKey(ctx, in.AccountID, canonical); err == nil {
		return existing, nil
	} else if !errors.Is(err, ErrNotFound) {
		return JobSubmission{}, err
	}

	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}

	var out JobSubmission
	err := s.WithAccount(ctx, in.AccountID, func(ctx context.Context, tx pgx.Tx) error {
		// FE4 fence: identical to SubmitJob — never take evidence custody for a
		// non-active account.
		var status string
		if e := tx.QueryRow(ctx,
			`SELECT status FROM accounts WHERE account_id = $1::uuid FOR UPDATE`,
			in.AccountID).Scan(&status); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return ErrAccountClosed
			}
			return fmt.Errorf("lock account: %w", e)
		}
		if status != "active" {
			return ErrAccountClosed
		}

		reservationID, e := reserveDigestAllowanceTx(ctx, tx, in.AccountID, now)
		if e != nil {
			return e
		}

		// sessionPK "" ⇒ NULL: a digest's evidence_objects row has no owning
		// session (createEvidenceTx already treats "" as NULL for SubmitJob's
		// legacy callers).
		evidencePK, e := createEvidenceTx(ctx, tx, in.AccountID, "", in.BlobRef, in.UploadDigest, in.ContentDigest, in.SizeBytes, now)
		if e != nil {
			return e
		}
		if len(in.EvidenceBytes) > 0 {
			if e := putEvidenceBlobTx(ctx, tx, s.enc, in.AccountID, in.BlobRef, in.EvidenceBytes, now); e != nil {
				return e
			}
		}

		var consentGen int64
		if e := tx.QueryRow(ctx,
			`SELECT consent_generation FROM accounts WHERE account_id = $1::uuid`,
			in.AccountID).Scan(&consentGen); e != nil {
			return fmt.Errorf("read consent generation: %w", e)
		}

		var jobID string
		e = tx.QueryRow(ctx,
			`INSERT INTO analysis_jobs
			   (account_id, session_pk, evidence_pk, feature, route_id, route_version, prompt_version,
			    canonical_job_key, consent_generation, upload_digest, state, reservation_id, available_at)
			 VALUES ($1::uuid, NULL, $2::uuid, $3, $4, $5, $6, $7, $8, $9, 'queued', $10::uuid, $11)
			 ON CONFLICT (account_id, canonical_job_key) DO NOTHING
			 RETURNING id::text`,
			in.AccountID, evidencePK, FeatureProjectDigest, in.RouteID, in.RouteVersion, in.PromptVersion,
			canonical, consentGen, in.UploadDigest, reservationID, now).Scan(&jobID)
		if errors.Is(e, pgx.ErrNoRows) {
			return errJobRace
		}
		if e != nil {
			return fmt.Errorf("insert digest job: %w", e)
		}
		if _, e := tx.Exec(ctx,
			`UPDATE usage_reservations SET job_id = $3::uuid WHERE account_id = $1::uuid AND id = $2::uuid`,
			in.AccountID, reservationID, jobID); e != nil {
			return fmt.Errorf("bind reservation: %w", e)
		}
		out = JobSubmission{JobID: jobID, State: "queued", ReservationID: reservationID}
		return nil
	})
	if errors.Is(err, errJobRace) {
		return s.jobByCanonicalKey(ctx, in.AccountID, canonical)
	}
	if err != nil {
		return JobSubmission{}, err
	}
	return out, nil
}
