package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/foundry"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// LunaExecutor is the CI-P4 Foundry inference executor. One bounded, non-agentic
// call per attempt: it reads the encrypted evidence bytes under the lease,
// builds the evidence-as-data prompt, calls Foundry, validates the strict
// structured output (cloudcontract.Result.Validate + SafeText normalization),
// scrubs derived text (a completion can reproduce a secret), and settles the
// result + reservation atomically. It NEVER retries internally — the worker owns
// the attempt loop and re-runs the full revalidation before each call.
//
// The pure per-call stages (prompt build, request build, completion
// normalize/scrub/ground) live in luna.go as package-level functions so the
// operator-only fixture proving lane exercises the SAME code, not a copy.
type LunaExecutor struct {
	store    *store.Store
	blobs    store.BlobStore
	provider foundry.Provider
}

// NewLunaExecutor builds the executor.
func NewLunaExecutor(s *store.Store, blobs store.BlobStore, provider foundry.Provider) *LunaExecutor {
	return &LunaExecutor{store: s, blobs: blobs, provider: provider}
}

var _ Executor = (*LunaExecutor)(nil)

// Execute performs one provider attempt. route + apiKey are the resolved route +
// credential the worker's per-attempt revalidation just confirmed; finalGate
// re-runs that revalidation at the dispatch seam (against a fresh clock sample)
// so the window between revalidation and the actual HTTP call is minimized
// (FA1/FA2/FA7). clock is re-sampled at the seam and for the completion write.
func (e *LunaExecutor) Execute(ctx context.Context, lj *store.LeasedJob, route store.RouteInfo, apiKey string, attempt int, clock func() time.Time, finalGate FinalGate) (ExecResult, error) {
	// Read evidence object (for the blob ref + a last deletion/TTL check).
	eo, err := e.store.GetEvidence(ctx, lj.AccountID, lj.EvidencePK)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ExecResult{Outcome: ExecEvidenceExpired}, nil
		}
		return ExecResult{}, fmt.Errorf("read evidence: %w", err)
	}
	if eo.DeletedAt != nil {
		return ExecResult{Outcome: ExecEvidenceExpired}, nil
	}

	// Get the encrypted bytes. Missing ⇒ evidence_expired (never a retryable
	// provider path — substrate §6.2).
	plaintext, err := e.blobs.Get(ctx, lj.AccountID, eo.BlobRef)
	if errors.Is(err, store.ErrBlobMissing) {
		return ExecResult{Outcome: ExecEvidenceExpired}, nil
	}
	if err != nil {
		return ExecResult{}, fmt.Errorf("get evidence bytes: %w", err)
	}

	// FE3: derive the EXACT bounded allowed-evidence-ref set from the uploaded
	// envelope BEFORE dispatch, so a result citing an invented/hallucinated ref
	// is rejected rather than stored as a fabricated-but-grounded-looking
	// citation. Parse the envelope from the plaintext (validated at admission);
	// a parse failure leaves the set empty ⇒ any cited ref is rejected (fail
	// closed).
	var env cloudcontract.Envelope
	_ = json.Unmarshal(plaintext, &env)
	allowedRefs := cloudcontract.AllowedEvidenceRefs(env)

	prompt, err := BuildLunaPrompt(plaintext)
	if err != nil {
		// A per-request delimiter could not be made unforgeable against this
		// evidence — treat as invalid output (never send an unfenced prompt).
		return ExecResult{Outcome: ExecInvalidOutput, Detail: "evidence delimiter collision"}, nil
	}

	// FA1/FA2/FA7: re-run the FULL execution-lease revalidation at the LAST point
	// before HTTP dispatch, against a FRESHLY sampled instant. blob-load +
	// prompt-build above consume time, so a route mutation/deactivation, a kill
	// switch flip, evidence expiry, a stale attestation, or a consent bump in
	// that window is caught here — the provider is never called against a snapshot
	// that went stale after the worker's per-attempt revalidation. The freshly
	// resolved route + credential are used for the call. A non-empty reason parks
	// the job (no provider call); the residual window between this check and the
	// physical write cannot be closed without a lock held across an external call,
	// and is backstopped at the RESULT layer by the lease-generation completion
	// CAS (a stale-snapshot dispatch's result can never be stored).
	dispatchNow := clock()
	freshRoute, freshKey, reason, err := finalGate(ctx, dispatchNow)
	if err != nil {
		return ExecResult{}, fmt.Errorf("final dispatch gate: %w", err)
	}
	if reason != "" {
		if reason == store.ReasonEvidenceExpired {
			return ExecResult{Outcome: ExecEvidenceExpired}, nil
		}
		return ExecResult{ParkReason: reason}, nil
	}
	// Dispatch under the FRESHLY resolved snapshot + credential the final gate
	// returned (not the worker's earlier per-attempt values, which are only used
	// for the pre-blob-load fast reject).
	route = freshRoute
	now := dispatchNow

	res, err := e.provider.Complete(ctx, BuildLunaRequest(route, freshKey, prompt))
	if err != nil {
		// A persistence violation (store:false not honored) is a security
		// failure — fail the job immediately, never retry into a persisting
		// endpoint (plan §2.3).
		if errors.Is(err, foundry.ErrPersistenceViolation) {
			return ExecResult{Outcome: ExecProviderError, Terminal: true, TerminalReason: store.ReasonPersistenceViolation, Detail: "store:false violated"}, nil
		}
		// Quota / timeout / transport / 5xx — retryable provider error.
		return ExecResult{Outcome: ExecProviderError, Detail: providerErrClass(err)}, nil
	}

	tokensIn, tokensOut := res.TokensIn, res.TokensOut

	// Parse → validate/normalize (FE1) → secret-scrub → ground every cited
	// evidence ref against the envelope's allowed set (FE3).
	cleaned, rejection := ProcessLunaCompletion(res.Content, allowedRefs)
	if rejection != "" {
		return ExecResult{Outcome: ExecInvalidOutput, TokensIn: tokensIn, TokensOut: tokensOut, Detail: rejection}, nil
	}

	// Marshal the OPAQUE normalized result — the JSON sink runs through
	// SafeText.MarshalJSON, so the stored/served bytes are the validated value
	// (FE1: a real production sink now uses the contract).
	resultJSON, err := json.Marshal(cleaned)
	if err != nil {
		return ExecResult{}, fmt.Errorf("marshal result: %w", err)
	}

	cost := tokenCost(tokensIn, tokensOut, route)
	prov := store.ResultProvenance{
		ModelRouteID: route.RouteID, RouteVersion: route.RouteVersion, PromptVersion: route.PromptVersion,
		PriceVersion: route.PriceVersion, PromptHash: prompt.PromptHash,
		TokensIn: tokensIn, TokensOut: tokensOut, CostUSD: cost, RetryCount: attempt,
	}
	_, committed, err := e.store.CompleteJobWithResult(ctx, lj.AccountID, lj.JobID, lj.EvidencePK, lj.ReservationID,
		lj.LeaseWorker, lj.LeaseGeneration, cleaned.SchemaVersion, resultJSON, prov, now)
	if err != nil {
		return ExecResult{}, fmt.Errorf("complete job: %w", err)
	}
	if !committed {
		// The completion CAS stored nothing: the job was canceled/deleted/
		// re-leased, the account was fenced, or consent bumped since revalidation
		// (FA1/FA8). Never resurrect it.
		return ExecResult{Outcome: ExecAborted, TokensIn: tokensIn, TokensOut: tokensOut, Detail: "completion superseded"}, nil
	}
	return ExecResult{Outcome: ExecSucceeded, TokensIn: tokensIn, TokensOut: tokensOut}, nil
}

func tokenCost(tokensIn, tokensOut int64, route store.RouteInfo) float64 {
	return float64(tokensIn)/1_000_000*route.InputPricePerMTok +
		float64(tokensOut)/1_000_000*route.OutputPricePerMTok
}

func providerErrClass(err error) string {
	switch {
	case errors.Is(err, foundry.ErrQuota):
		return "quota"
	case errors.Is(err, foundry.ErrTimeout):
		return "timeout"
	}
	// A non-2xx provider response carries the status + provider error body, which
	// is the ONLY way an operator can tell a config/shape rejection (400) from an
	// auth failure (401/403) or an upstream outage (5xx) after the fact. The body
	// is the PROVIDER's error JSON (e.g. {"error":{"message":...}}), not session
	// evidence; it is truncated and (like every attempt detail) jsonSafe-escaped
	// before it reaches the ledger.
	var pe *foundry.ProviderError
	if errors.As(err, &pe) {
		return fmt.Sprintf("provider_status_%d: %s", pe.StatusCode, truncateDetail(pe.Body, 300))
	}
	// Transport/dial/TLS failures (no HTTP response) — keep the class but carry
	// the error text so an egress/DNS problem is not indistinguishable from a 4xx.
	return "provider_error: " + truncateDetail(err.Error(), 200)
}

// truncateDetail bounds a diagnostic string for the attempt ledger.
func truncateDetail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
