package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/inference"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// Pricer prices one completed provider call from the shared pricing table
// (internal/intelligence/cost, composed by cmd/observer-cloud so this package
// stays free of it). It returns the USD cost, the price version the figure was
// computed under (recorded on the result's provenance), and ok=false when the
// table has no row for the route's model. It is consulted ONLY for a route whose
// dialect declares DeploymentIsModelID (the deployment IS the public model id,
// e.g. "claude-haiku-5-5"); every other route keeps its own price snapshot.
type Pricer func(route store.RouteInfo, res inference.Response, at time.Time) (usd float64, priceVersion string, ok bool)

// priceCall resolves the cost + price version for one completed call: the
// table price when the route's dialect prices by model id and the pricer knows
// the model, otherwise the route's own per-MTok snapshot (the Foundry routes,
// whose deployment names are operator labels, not model ids).
func priceCall(p Pricer, route store.RouteInfo, res inference.Response, at time.Time) (float64, string) {
	if spec, ok := inference.SpecFor(route.Dialect); ok && spec.DeploymentIsModelID && p != nil {
		if usd, ver, ok := p(route, res, at); ok {
			return usd, ver
		}
	}
	return tokenCost(res.TokensIn, res.TokensOut, route), route.PriceVersion
}

// LunaExecutor is the CI-P4 inference executor. One bounded, non-agentic
// call per attempt: it reads the encrypted evidence bytes under the lease,
// builds the evidence-as-data prompt, calls the route's provider through the
// inference seam (Foundry or Anthropic, by the route's dialect), validates the strict
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
	provider inference.Provider
	pricer   Pricer
}

// NewLunaExecutor builds the executor.
func NewLunaExecutor(s *store.Store, blobs store.BlobStore, provider inference.Provider) *LunaExecutor {
	return &LunaExecutor{store: s, blobs: blobs, provider: provider}
}

// WithPricer wires the pricing-table pricer and returns the executor.
func (e *LunaExecutor) WithPricer(p Pricer) *LunaExecutor {
	e.pricer = p
	return e
}

var _ Executor = (*LunaExecutor)(nil)

// Execute performs one provider attempt. route + apiKey are the resolved route +
// credential the worker's per-attempt revalidation just confirmed; finalGate
// re-runs that revalidation at the dispatch seam (against a fresh clock sample)
// so the window between revalidation and the actual HTTP call is minimized
// (FA1/FA2/FA7). clock is re-sampled at the seam and for the completion write.
func (e *LunaExecutor) Execute(ctx context.Context, lj *store.LeasedJob, route store.RouteInfo, apiKey string, attempt int, clock func() time.Time, finalGate FinalGate) (ExecResult, error) { //nolint:staticcheck // SA4009: the dispatch deliberately uses the route the final gate re-resolves, never the earlier per-attempt one (FA1/FA2/FA7)
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
	route = freshRoute //nolint:staticcheck // SA4009: see the Execute signature
	now := dispatchNow

	res, err := e.provider.Complete(ctx, BuildLunaRequest(route, freshKey, prompt))
	if err != nil {
		// A persistence violation (store:false not honored) is a security
		// failure — fail the job immediately, never retry into a persisting
		// endpoint (plan §2.3).
		if errors.Is(err, inference.ErrPersistenceViolation) {
			return ExecResult{Outcome: ExecProviderError, Terminal: true, TerminalReason: store.ReasonPersistenceViolation, Detail: "store:false violated"}, nil
		}
		// Quota / timeout / transport / 5xx — retryable provider error.
		return ExecResult{Outcome: ExecProviderError, Detail: providerErrClass(err)}, nil
	}

	tokensIn, tokensOut := res.TokensIn, res.TokensOut

	// Parse → validate/normalize (FE1) → secret-scrub → ground every cited
	// evidence ref against the envelope's allowed set (FE3).
	cleaned, notes, rejection := ProcessLunaCompletionNoted(res.Content, allowedRefs)
	if rejection != "" {
		// The rejected call was still billed: carry its cost so the worker
		// counts it against the pool's spend ceiling (T-946).
		attemptCost, _ := priceCall(e.pricer, route, res, now)
		return ExecResult{Outcome: ExecInvalidOutput, TokensIn: tokensIn, TokensOut: tokensOut, CostUSD: attemptCost, Detail: InvalidOutputDetail(res, rejection)}, nil
	}

	// Marshal the OPAQUE normalized result — the JSON sink runs through
	// SafeText.MarshalJSON, so the stored/served bytes are the validated value
	// (FE1: a real production sink now uses the contract).
	resultJSON, err := json.Marshal(cleaned)
	if err != nil {
		return ExecResult{}, fmt.Errorf("marshal result: %w", err)
	}

	cost, priceVersion := priceCall(e.pricer, route, res, now)
	prov := store.ResultProvenance{
		ModelRouteID: route.RouteID, RouteVersion: route.RouteVersion, PromptVersion: route.PromptVersion,
		PriceVersion: priceVersion, PromptHash: prompt.PromptHash,
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
	return ExecResult{Outcome: ExecSucceeded, TokensIn: tokensIn, TokensOut: tokensOut, TitleFallback: notes.TitleFallback}, nil
}

// InvalidOutputDetail is the attempt-ledger detail for a rejected completion.
// A completion cut at the route's max_output_tokens is incomplete JSON, so the
// post-call stage already rejects it (invalid output: retried within the
// attempt budget, then the job fails and the user unit is refunded; a partial
// answer is never stored). This only names the cause, so an operator can see
// how often the cap truncates an answer (operator ruling D-313, T-414: the cap
// is deliberate and the residual risk is accepted).
//
// A provider REFUSAL (the Anthropic safety classifiers declining, HTTP 200 with
// stop_reason "refusal") carries no JSON either; it is named the same way so
// the ledger says the provider declined rather than that the model wrote
// garbage. It is retried within the attempt budget like any invalid output,
// then fails with the user unit refunded.
func InvalidOutputDetail(res inference.Response, rejection string) string {
	switch {
	case res.Truncated():
		return "truncated at max_output_tokens (finish_reason=length): " + rejection
	case res.Refused():
		return "provider refused (finish_reason=" + res.FinishReason + "): " + rejection
	}
	return rejection
}

func tokenCost(tokensIn, tokensOut int64, route store.RouteInfo) float64 {
	return float64(tokensIn)/1_000_000*route.InputPricePerMTok +
		float64(tokensOut)/1_000_000*route.OutputPricePerMTok
}

func providerErrClass(err error) string {
	switch {
	case errors.Is(err, inference.ErrQuota):
		return "quota"
	case errors.Is(err, inference.ErrTimeout):
		return "timeout"
	case errors.Is(err, inference.ErrUnsupportedDialect):
		// The route's dialect has no provider wired in this process (e.g. a
		// Foundry route on an Anthropic-only deployment). The credential gate
		// normally parks such a route before dispatch; this names the case if
		// it is ever reached.
		return "unsupported_dialect: " + truncateDetail(err.Error(), 160)
	}
	// A non-2xx provider response carries the status + provider error body, which
	// is the ONLY way an operator can tell a config/shape rejection (400) from an
	// auth failure (401/403) or an upstream outage (5xx) after the fact. The body
	// is the PROVIDER's error JSON (e.g. {"error":{"message":...}}), not session
	// evidence; it is truncated and (like every attempt detail) jsonSafe-escaped
	// before it reaches the ledger.
	var pe *inference.ProviderError
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
