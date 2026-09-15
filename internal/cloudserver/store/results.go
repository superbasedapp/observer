package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ResultsAccountSeqLockKey is the advisory-lock key an account's per-account
// results-cursor allocation serializes on (E1 / W6b). Two workers completing
// jobs for the SAME account take this lock before reading MAX(account_seq), so
// they mint consecutive values rather than colliding. Its distinct prefix keeps
// it in a different key space from the structural-grant/window/period locks
// (StructuralGrantLockKey et al.), so the two families never contend. The
// argument to pg_advisory_xact_lock is hashtext(key)::bigint.
//
// Exported for the same reason as StructuralGrantLockKey: the deterministic
// concurrency gate holds this lock from an outside connection and asserts a
// completion blocks on it — the only reliable way to prove the lock is taken
// before the MAX read, since two same-account completions fired together land
// milliseconds apart and usually don't reproduce a lost update.
func ResultsAccountSeqLockKey(accountID string) string {
	return "sbci-result-account-seq\x1f" + accountID
}

// ResultProvenance is the per-result provenance the worker settles (plan §6
// CI-P4): route/prompt/price versions, prompt hash, token counts, computed
// cost, and the retry count that produced the accepted output. It carries no
// evidence content and no prompt text.
type ResultProvenance struct {
	ModelRouteID  string
	RouteVersion  int64
	PromptVersion int64
	PriceVersion  string
	PromptHash    string
	TokensIn      int64
	TokensOut     int64
	CostUSD       float64
	RetryCount    int
}

// CompleteJobWithResult is the CI-P4 success transition, atomic in one tenant
// transaction (FA8). It COMPARE-AND-SETS the job on
// (account_id, id, state='running', lease_worker, lease_generation,
// lease_expires_at>now) AND revalidates the account is still active with the
// SAME consent generation the job was admitted under — inside the transaction,
// immediately before the write. The lease_generation bind is what stops a
// stale attempt whose job was re-leased (even by the SAME worker id, with a
// refreshed expiry) from storing its result: the re-lease bumped the
// generation, so the stale attempt's CAS affects zero rows.
// Only when that CAS affects a row does it store the validated+scrubbed result,
// SETTLE the reservation (one user unit — never a second on retry), append the
// ledger row, and delete the temporary evidence + bytes.
//
// If authorization changed since the executor's last revalidation (the job was
// canceled/deleted, re-leased by another worker, its lease expired, the account
// was suspended/fenced for deletion, or consent was re-confirmed), the CAS
// affects ZERO rows: nothing is stored, the reservation is untouched (it will
// be released by whatever transition superseded the job), and committed=false
// is returned. This is the no-store path a completion-after-cancel/deletion
// must take; the UNIQUE(account_id, job_id) constraint (migration 0007) is the
// final backstop against a duplicate result from any residual race.
func (s *Store) CompleteJobWithResult(ctx context.Context, accountID, jobID, evidencePK, reservationID, leaseWorker string, leaseGeneration int64, schemaVersion string, resultJSON []byte, prov ResultProvenance, now time.Time) (string, bool, error) {
	return s.completeJobWithResultTx(ctx, accountID, jobID, evidencePK, reservationID, leaseWorker, leaseGeneration,
		schemaVersion, resultJSON, prov, resultKindMeta{Kind: ResultKindSessionEnrichment}, now)
}

// CompleteDigestJobWithResult is CompleteJobWithResult's W5 sibling for the
// project_digest feature: the SAME CAS/settle/ledger/evidence-delete
// discipline, but the stored analysis_results row additionally carries
// kind='project_digest' and the project/period linkage. cloudProjectID
// resolves (idempotently, via ensureProjectTx) to the project's pk inside the
// SAME transaction — a digest job never carries its project on the job row
// itself (analysis_jobs is unchanged by migration 0037), so the executor
// passes it through from the DigestEvidence it already decoded.
func (s *Store) CompleteDigestJobWithResult(ctx context.Context, accountID, jobID, evidencePK, reservationID, leaseWorker string, leaseGeneration int64, schemaVersion string, resultJSON []byte, prov ResultProvenance, cloudProjectID, periodStart, periodEnd string, now time.Time) (string, bool, error) {
	return s.completeJobWithResultTx(ctx, accountID, jobID, evidencePK, reservationID, leaseWorker, leaseGeneration,
		schemaVersion, resultJSON, prov,
		resultKindMeta{Kind: ResultKindProjectDigest, CloudProjectID: cloudProjectID, PeriodStart: periodStart, PeriodEnd: periodEnd},
		now)
}

// resultKindMeta carries the analysis_results.kind discriminator plus the
// digest-only project/period linkage (migration 0037) through
// completeJobWithResultTx. The zero value (Kind="") is treated as
// ResultKindSessionEnrichment.
type resultKindMeta struct {
	Kind           string
	CloudProjectID string // "" ⇒ NULL project_pk
	PeriodStart    string // "" ⇒ NULL
	PeriodEnd      string // "" ⇒ NULL
}

// completeJobWithResultTx is the shared CI-P4 success transition behind both
// CompleteJobWithResult and CompleteDigestJobWithResult.
func (s *Store) completeJobWithResultTx(ctx context.Context, accountID, jobID, evidencePK, reservationID, leaseWorker string, leaseGeneration int64, schemaVersion string, resultJSON []byte, prov ResultProvenance, meta resultKindMeta, now time.Time) (string, bool, error) {
	var resultID string
	committed := false
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		ct, e := tx.Exec(ctx,
			`UPDATE analysis_jobs j
			    SET state = 'succeeded', terminal_reason = NULL,
			        lease_worker = NULL, lease_expires_at = NULL, updated_at = $3
			  WHERE j.account_id = $1::uuid AND j.id = $2::uuid
			    AND j.state = 'running'
			    AND j.lease_worker = $4
			    AND j.lease_generation = $5
			    AND j.lease_expires_at > clock_timestamp()
			    AND j.consent_generation = (SELECT a.consent_generation FROM accounts a WHERE a.account_id = j.account_id)
			    AND (SELECT a.status FROM accounts a WHERE a.account_id = j.account_id) = 'active'`,
			accountID, jobID, now, leaseWorker, leaseGeneration)
		if e != nil {
			return fmt.Errorf("complete CAS: %w", e)
		}
		if ct.RowsAffected() == 0 {
			// Authorization changed since revalidation — discard the completion.
			return nil
		}
		// Propose the next per-account cursor under the same advisory lock as
		// older workers. Migration 0038's insert trigger owns allocation and
		// enforces the durable account high-water mark even for old binaries
		// proposing MAX(account_seq)+1 after retention removed their rows.
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`,
			ResultsAccountSeqLockKey(accountID)); e != nil {
			return fmt.Errorf("lock account_seq allocation: %w", e)
		}
		var nextAccountSeq int64
		if e := tx.QueryRow(ctx,
			`SELECT coalesce((SELECT last_sequence FROM account_result_cursors WHERE account_id = $1::uuid), 0) + 1`,
			accountID).Scan(&nextAccountSeq); e != nil {
			return fmt.Errorf("read next account_seq: %w", e)
		}
		kind := meta.Kind
		if kind == "" {
			kind = ResultKindSessionEnrichment
		}
		var projectPKArg any
		if meta.CloudProjectID != "" {
			pk, e := ensureProjectTx(ctx, tx, accountID, meta.CloudProjectID)
			if e != nil {
				return e
			}
			projectPKArg = pk
		}
		var periodStartArg, periodEndArg any
		if meta.PeriodStart != "" {
			periodStartArg = meta.PeriodStart
		}
		if meta.PeriodEnd != "" {
			periodEndArg = meta.PeriodEnd
		}
		if e := tx.QueryRow(ctx,
			`INSERT INTO analysis_results
			   (account_id, job_id, result, schema_version, ai_source, account_seq,
			    model_route_id, route_version, prompt_version, price_version,
			    prompt_hash, tokens_in, tokens_out, cost_usd, retry_count,
			    kind, project_pk, period_start, period_end)
			 VALUES ($1::uuid, $2::uuid, $3::jsonb, $4, true, $5,
			         $6, $7, $8, $9, $10, $11, $12, $13, $14,
			         $15, $16::uuid, $17::date, $18::date)
			 RETURNING id::text`,
			accountID, jobID, resultJSON, schemaVersion, nextAccountSeq,
			prov.ModelRouteID, prov.RouteVersion, prov.PromptVersion, prov.PriceVersion,
			prov.PromptHash, prov.TokensIn, prov.TokensOut, prov.CostUSD, prov.RetryCount,
			kind, projectPKArg, periodStartArg, periodEndArg).Scan(&resultID); e != nil {
			return fmt.Errorf("insert result: %w", e)
		}
		// D21 regeneration supersede path (W6c): a newer result for the same
		// cloud session marks the prior current result(s) superseded, pointing
		// superseded_by at this one. The worker's column-level UPDATE grant
		// (migration 0018) lets it flip only superseded/superseded_by, never a
		// result body, and any user revisions on the superseded result survive
		// (R6: regeneration never displaces a user edit).
		if _, e := supersedePriorSessionResultsTx(ctx, tx, accountID, jobID, resultID); e != nil {
			return e
		}
		if reservationID != "" {
			if e := finalizeReservationTx(ctx, tx, accountID, reservationID, "settled", false); e != nil {
				return e
			}
		}
		rv := prov.RouteVersion
		attempts := prov.RetryCount + 1
		// InternalUnits=1 counts ONLY this (successful) attempt; each prior
		// failed attempt logged its own 'attempt' row, so the ledger's internal
		// units sum to the total attempts without double-counting.
		if e := appendLedgerTx(ctx, tx, accountID, ledgerEntry{
			JobID: jobID, Event: "settled", UserUnits: 1, InternalUnits: 1,
			RouteVersion: &rv, Attempts: &attempts,
			TokensIn: &prov.TokensIn, TokensOut: &prov.TokensOut,
			Detail: `{"scope":"settle"}`,
		}); e != nil {
			return e
		}
		if e := deleteEvidenceForJobTx(ctx, tx, accountID, evidencePK, now); e != nil {
			return e
		}
		committed = true
		return nil
	})
	return resultID, committed, err
}

// RecordProviderAttempt appends an append-only internal-cost ledger row for one
// provider attempt (first or retry) that did NOT produce an accepted result. It
// consumes internal units + tokens, NEVER a user unit (plan §6 CI-P4: retries
// settle internal cost but never a second user unit).
func (s *Store) RecordProviderAttempt(ctx context.Context, accountID, jobID string, tokensIn, tokensOut, routeVersion int64, attempt int, detail string) error {
	return s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		rv := routeVersion
		at := attempt
		ti, to := tokensIn, tokensOut
		if detail == "" {
			detail = `{"scope":"attempt"}`
		}
		return appendLedgerTx(ctx, tx, accountID, ledgerEntry{
			JobID: jobID, Event: "attempt", UserUnits: 0, InternalUnits: 1,
			RouteVersion: &rv, Attempts: &at, TokensIn: &ti, TokensOut: &to, Detail: detail,
		})
	})
}

// ResultRow is one row of GET /v1/results?after=<cursor>. It carries the
// cloud_session_id (via the job → cloud_sessions join) so the node can
// associate the result with a local session (the CI-P5 gap the CI-P4 wire
// record closes) plus the provenance columns.
type ResultRow struct {
	// Cursor is the GLOBAL identity sequence (analysis_results.seq) — the
	// legacy pull cursor kept for the dual-read back-compat window (E1 / W6b).
	Cursor int64
	// AccountSeq is the ADDITIVE per-account results cursor (migration 0016).
	// Dense 1..N per account, independent of cross-tenant volume; the account
	// path (ListResultsAfterAccountSeq) reads and advances on it.
	AccountSeq     int64
	ID             string
	JobID          string
	CloudSessionID string
	SchemaVersion  string
	AISource       bool
	Superseded     bool
	// CorrectionSeq is the result's ETag component (W6c): 0 for the pristine AI
	// original, +1 per accepted user correction. The wire ETag is
	// cloudcontract.ResultETag(ID, CorrectionSeq); the node passes it back as
	// If-Match when it syncs a local override up as a revision.
	CorrectionSeq int64
	CreatedAt     time.Time
	Result        json.RawMessage
	Provenance    ResultProvenance

	// Kind classifies the result (migration 0037, W5): ResultKindSessionEnrichment
	// or ResultKindProjectDigest.
	Kind string
	// CloudProjectID is the digest's project pseudonym, set only when Kind is
	// ResultKindProjectDigest (resolved via the row's project_pk).
	CloudProjectID string
	// PeriodStart / PeriodEnd are the digest's ISO week bounds ("YYYY-MM-DD"),
	// set only for a project-digest row.
	PeriodStart string
	PeriodEnd   string
}

// resultRowColumns is the shared SELECT column list both cursor paths read.
// Every row carries BOTH cursors (r.seq and r.account_seq) so a caller on
// either path can advance its own and the wire can dual-emit (E1 / W6b). The
// LEFT JOIN to cloud_projects (via r.project_pk, migration 0037) resolves a
// digest row's project pseudonym; it is NULL/empty for a session-enrichment
// row (whose project_pk is NULL).
const resultRowColumns = `r.seq, r.account_seq, r.id::text, r.job_id::text, coalesce(cs.cloud_session_id, ''),
	        r.schema_version, r.ai_source, r.superseded, r.correction_seq, r.created_at, r.result,
	        r.model_route_id, r.route_version, r.prompt_version, r.price_version,
	        r.prompt_hash, r.tokens_in, r.tokens_out, r.cost_usd, r.retry_count,
	        r.kind, coalesce(dcp.cloud_project_id, ''),
	        coalesce(to_char(r.period_start, 'YYYY-MM-DD'), ''), coalesce(to_char(r.period_end, 'YYYY-MM-DD'), '')
	   FROM analysis_results r
	   JOIN analysis_jobs j ON j.account_id = r.account_id AND j.id = r.job_id
	   LEFT JOIN cloud_sessions cs ON cs.account_id = j.account_id AND cs.id = j.session_pk
	   LEFT JOIN cloud_projects dcp ON dcp.account_id = r.account_id AND dcp.id = r.project_pk`

// scanResultRows scans the resultRowColumns projection into ResultRows.
func scanResultRows(rows pgx.Rows) ([]ResultRow, error) {
	defer rows.Close()
	var out []ResultRow
	for rows.Next() {
		var r ResultRow
		var raw []byte
		var p ResultProvenance
		if e := rows.Scan(&r.Cursor, &r.AccountSeq, &r.ID, &r.JobID, &r.CloudSessionID,
			&r.SchemaVersion, &r.AISource, &r.Superseded, &r.CorrectionSeq, &r.CreatedAt, &raw,
			&p.ModelRouteID, &p.RouteVersion, &p.PromptVersion, &p.PriceVersion,
			&p.PromptHash, &p.TokensIn, &p.TokensOut, &p.CostUSD, &p.RetryCount,
			&r.Kind, &r.CloudProjectID, &r.PeriodStart, &r.PeriodEnd); e != nil {
			return nil, e
		}
		r.Result = json.RawMessage(raw)
		r.Provenance = p
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListResultsAfter returns the account's results with GLOBAL seq > cursor,
// ascending, bounded by limit. This is the LEGACY path kept for the dual-read
// back-compat window (E1 / W6b): an in-flight node that still passes a bare
// decimal `after` keeps getting global-seq cursors. New pulls use
// ListResultsAfterAccountSeq. It LEFT JOINs the producing job's cloud session so
// each row carries its cloud_session_id; RLS scopes every joined table.
func (s *Store) ListResultsAfter(ctx context.Context, accountID string, cursor int64, limit int) ([]ResultRow, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var out []ResultRow
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT `+resultRowColumns+`
			  WHERE r.account_id = $1::uuid AND r.seq > $2
			  ORDER BY r.seq ASC LIMIT $3`,
			accountID, cursor, limit)
		if e != nil {
			return e
		}
		got, e := scanResultRows(rows)
		if e != nil {
			return e
		}
		out = got
		return nil
	})
	return out, err
}

// ListResultsAfterAccountSeq returns the account's results with ADDITIVE
// per-account account_seq > cursor, ascending, bounded by limit (E1 / W6b). It
// is the new default cursor path: account_seq is dense 1..N per account and
// independent of cross-tenant volume, so the pull cursor leaks nothing about
// how many results other tenants produced (the side-channel the global `seq`
// carries). Same joins/RLS as ListResultsAfter.
func (s *Store) ListResultsAfterAccountSeq(ctx context.Context, accountID string, cursor int64, limit int) ([]ResultRow, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var out []ResultRow
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT `+resultRowColumns+`
			  WHERE r.account_id = $1::uuid AND r.account_seq > $2
			  ORDER BY r.account_seq ASC LIMIT $3`,
			accountID, cursor, limit)
		if e != nil {
			return e
		}
		got, e := scanResultRows(rows)
		if e != nil {
			return e
		}
		out = got
		return nil
	})
	return out, err
}
