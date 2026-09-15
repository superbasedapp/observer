package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// corrections.go is the W6c server half (divergence-remediation plan §3 W6c;
// operator ruling R6, closing D4/D12/D21): the immutable AI result keeps its
// original body forever, a user edit is an APPEND-ONLY revision guarded by an
// ETag (the result's correction_seq), and a regeneration marks the prior result
// superseded without displacing a user edit.

var (
	// ErrResultTombstoned is returned when a correction targets a result whose
	// body has been tombstoned by account deletion — there is nothing to correct.
	ErrResultTombstoned = errors.New("cloudserver/store: result is tombstoned")
	// ErrResultETagMismatch is returned when the caller's If-Match correction
	// sequence does not equal the result's current one — a concurrent editor
	// moved the head, so the caller must re-read and retry (HTTP 412).
	ErrResultETagMismatch = errors.New("cloudserver/store: result etag mismatch")
	// ErrResultNotCorrectable is returned when a correction targets a result
	// whose kind is not session_enrichment (W5: a project_digest result is a
	// server-computed rollup over several sessions' own results — there is no
	// single title/description slot for a developer to correct, and a
	// correction to one would not know which session it was "about"). Refused
	// rather than silently accepted.
	ErrResultNotCorrectable = errors.New("cloudserver/store: result kind is not correctable")
)

// tombstoneResult is the marker a result/revision body carries when it has been
// tombstoned rather than purged. Account deletion (W6d) PURGES result rows
// outright, so this is a DEFENSIVE marker for the W6c read surface: if any path
// ever leaves a result body as this marker, the reads treat it as tombstoned
// (body omitted, `tombstoned:true`) rather than serving the marker as content.
// Detection lives here (corrections.go / sessions.go read it); nothing in the
// normal deletion path sets it any more.
const tombstoneResult = `{"tombstoned":true}`

// CorrectionSource is where a correction originated (result_revisions.source).
type CorrectionSource string

const (
	// CorrectionSourcePortal marks an edit made on the portal Sessions page.
	CorrectionSourcePortal CorrectionSource = "portal"
	// CorrectionSourceNode marks a node-side override synced up as a revision
	// (R6: "node override syncs up as a revision on next sync").
	CorrectionSourceNode CorrectionSource = "node"
)

func (s CorrectionSource) valid() bool {
	return s == CorrectionSourcePortal || s == CorrectionSourceNode
}

// CorrectionOutcome is what ApplyResultCorrection settled.
type CorrectionOutcome struct {
	// RevisionSeq is the per-result number of the revision this correction
	// produced (on a replay, the number of the revision the idempotency key
	// originally produced).
	RevisionSeq int
	// CorrectionSeq is the result's head correction sequence AFTER this call —
	// the ETag component the caller returns so the next If-Match matches. On a
	// replay it is the CURRENT head (which may be higher than the value this key
	// originally produced, if later corrections landed).
	CorrectionSeq int64
	// Replayed is true when the idempotency key had already been applied to this
	// result and no new revision was written.
	Replayed bool
}

// ApplyResultCorrection appends one user correction to a result as a new,
// higher-numbered revision, in ONE tenant transaction (R6). The parent
// analysis_results row is taken FOR UPDATE first, which serializes revision
// allocation and the correction_seq bump against any concurrent correction to
// the SAME result — so two racing editors mint consecutive revisions and the
// ETag advances exactly once per accepted edit.
//
// Ordering inside the transaction is deliberate:
//   - idempotency replay is checked BEFORE If-Match, so a client retrying the
//     SAME correction (same idempotency key, carrying its now-stale original
//     If-Match) still succeeds as a replay rather than getting a 412;
//   - the tombstone check gates only NEW corrections — a replay of a key that
//     landed before deletion is harmless (nothing is written);
//   - If-Match is then enforced fail-closed: a mismatch writes nothing and
//     returns ErrResultETagMismatch with the current head so the API can hand
//     the caller the fresh ETag.
//
// correctionJSON is the already-normalized (SafeText) NormalizedCorrection
// bytes — the API boundary runs cloudcontract normalization before calling, so
// the store never persists un-normalized user text. The AI original in
// analysis_results.result is NEVER touched; corrections live only in
// result_revisions.
func (s *Store) ApplyResultCorrection(ctx context.Context, accountID, resultID string, ifMatchSeq int64, idempotencyKey string, correctionJSON []byte, source CorrectionSource, now time.Time) (CorrectionOutcome, error) {
	if idempotencyKey == "" {
		return CorrectionOutcome{}, errors.New("cloudserver/store.ApplyResultCorrection: empty idempotency key")
	}
	if !source.valid() {
		return CorrectionOutcome{}, fmt.Errorf("cloudserver/store.ApplyResultCorrection: invalid source %q", source)
	}
	if now.IsZero() {
		now = time.Now()
	}
	var out CorrectionOutcome
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		// 1) Lock the parent result. FOR UPDATE both proves existence (RLS-scoped)
		// and serializes revision allocation + the head bump for this result.
		var curSeq int64
		var tombstoned bool
		var kind string
		if e := tx.QueryRow(ctx,
			`SELECT correction_seq, (result = $3::jsonb), kind
			   FROM analysis_results
			  WHERE account_id = $1::uuid AND id = $2::uuid
			  FOR UPDATE`,
			accountID, resultID, tombstoneResult).Scan(&curSeq, &tombstoned, &kind); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("lock result: %w", e)
		}

		// 1b) A non-session_enrichment result (a project digest, W5) has no
		// single title/description slot to correct — refuse structurally,
		// before idempotency/tombstone/ETag are even consulted.
		if kind != ResultKindSessionEnrichment {
			return ErrResultNotCorrectable
		}

		// 2) Idempotency replay — BEFORE If-Match, so a retry of the same edit
		// with its stale original If-Match still replays instead of 412ing.
		var priorRev int
		e := tx.QueryRow(ctx,
			`SELECT revision_seq FROM result_revisions
			  WHERE account_id = $1::uuid AND result_id = $2::uuid AND idempotency_key = $3`,
			accountID, resultID, idempotencyKey).Scan(&priorRev)
		switch {
		case e == nil:
			out = CorrectionOutcome{RevisionSeq: priorRev, CorrectionSeq: curSeq, Replayed: true}
			return nil
		case errors.Is(e, pgx.ErrNoRows):
			// fall through to a fresh correction
		default:
			return fmt.Errorf("idempotency lookup: %w", e)
		}

		// 3) A tombstoned result accepts no NEW correction.
		if tombstoned {
			return ErrResultTombstoned
		}

		// 4) If-Match fail-closed: the caller must have seen the current head.
		if ifMatchSeq != curSeq {
			out = CorrectionOutcome{CorrectionSeq: curSeq}
			return ErrResultETagMismatch
		}

		// 5) Allocate the next per-result revision number under the row lock.
		var nextRev int
		if e := tx.QueryRow(ctx,
			`SELECT coalesce(max(revision_seq), 0) + 1 FROM result_revisions
			  WHERE account_id = $1::uuid AND result_id = $2::uuid`,
			accountID, resultID).Scan(&nextRev); e != nil {
			return fmt.Errorf("allocate revision_seq: %w", e)
		}

		// 6) Append the revision (never an UPDATE of an existing one).
		if _, e := tx.Exec(ctx,
			`INSERT INTO result_revisions
			   (account_id, result_id, revision_seq, editor, source, correction, idempotency_key, created_at)
			 VALUES ($1::uuid, $2::uuid, $3, 'user', $4, $5::jsonb, $6, $7)`,
			accountID, resultID, nextRev, string(source), correctionJSON, idempotencyKey, now); e != nil {
			return fmt.Errorf("insert revision: %w", e)
		}

		// 7) Bump the head ETag. The AI original body is untouched.
		var newSeq int64
		if e := tx.QueryRow(ctx,
			`UPDATE analysis_results SET correction_seq = correction_seq + 1
			  WHERE account_id = $1::uuid AND id = $2::uuid
			  RETURNING correction_seq`,
			accountID, resultID).Scan(&newSeq); e != nil {
			return fmt.Errorf("bump correction_seq: %w", e)
		}
		out = CorrectionOutcome{RevisionSeq: nextRev, CorrectionSeq: newSeq, Replayed: false}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrResultTombstoned) ||
			errors.Is(err, ErrResultETagMismatch) || errors.Is(err, ErrResultNotCorrectable) {
			return out, err
		}
		return CorrectionOutcome{}, fmt.Errorf("cloudserver/store.ApplyResultCorrection: %w", err)
	}
	return out, nil
}

// supersedePriorSessionResultsTx marks every OTHER current result of the same
// cloud session superseded by newResultID — the D21 regeneration path, run
// inside CompleteJobWithResult's transaction right after the new result is
// inserted. It uses the worker's column-level UPDATE grant (superseded,
// superseded_by only — migration 0018), so it can never touch a result body.
//
// A regeneration never displaces a user EDIT: superseding the prior AI result
// only flips its provenance flag; any user revisions on it survive, and the
// read-side effective-head rule (SessionDetail) still surfaces the latest
// explicit user act. Results with a NULL session_pk are never grouped (there is
// no session to regenerate within), so they are left untouched.
func supersedePriorSessionResultsTx(ctx context.Context, tx pgx.Tx, accountID, newJobID, newResultID string) (int, error) {
	ct, err := tx.Exec(ctx,
		`UPDATE analysis_results r
		    SET superseded = true, superseded_by = $3::uuid
		   FROM analysis_jobs j, analysis_jobs jnew
		  WHERE r.account_id = $1::uuid
		    AND j.account_id = $1::uuid AND j.id = r.job_id
		    AND jnew.account_id = $1::uuid AND jnew.id = $2::uuid
		    AND jnew.session_pk IS NOT NULL
		    AND j.session_pk = jnew.session_pk
		    AND r.id <> $3::uuid
		    AND r.superseded = false`,
		accountID, newJobID, newResultID)
	if err != nil {
		return 0, fmt.Errorf("supersede prior session results: %w", err)
	}
	return int(ct.RowsAffected()), nil
}

// ResultRevision is one row of a result's append-only correction history.
type ResultRevision struct {
	RevisionSeq int             `json:"revision_seq"`
	Editor      string          `json:"editor"`
	Source      string          `json:"source"`
	Correction  json.RawMessage `json:"correction"`
	CreatedAt   time.Time       `json:"created_at"`
}

// ListResultRevisions returns a result's revisions newest-first (RLS-scoped).
func (s *Store) ListResultRevisions(ctx context.Context, accountID, resultID string) ([]ResultRevision, error) {
	var out []ResultRevision
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		revs, e := loadRevisionsTx(ctx, tx, accountID, resultID)
		if e != nil {
			return e
		}
		out = revs
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.ListResultRevisions: %w", err)
	}
	return out, nil
}
