package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/dataauthority"
)

// handleSubmitJob is the enrichment admission path (plan §6 CI-P3): PoP +
// idempotency + two-digest recomputation over the submitted bytes +
// out-of-purpose rejection + reservation + evidence write + enqueue. The
// request body IS the exact serialized envelope (the same bytes the node
// previewed and whose upload digest the consent receipt binds).
func (s *Server) handleSubmitJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, _ := principalFrom(ctx)

	// Global free-tier kill switch (plan §6 CI-P6): when the operator has paused
	// the free tier, refuse NEW submissions up front with an honest 503 — before
	// consuming a reservation or writing evidence. Fail closed: a check error
	// blocks rather than silently admits. (The worker separately gates leased
	// jobs on the global + per-route switches; this is the admission wall.)
	if active, err := s.store.GlobalKillSwitchActive(ctx); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "unavailable", "could not verify service state")
		return
	} else if active {
		s.audit(ctx, p.AccountID, "job_rejected_kill_switch")
		writeErr(w, http.StatusServiceUnavailable, "service_paused",
			"cloud intelligence is temporarily paused; no new jobs are being accepted right now")
		return
	}

	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "could not read body")
		return
	}

	var env cloudcontract.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "envelope is not valid JSON")
		return
	}
	if err := env.Validate(); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "invalid_envelope", err.Error())
		return
	}

	// Defense-in-depth: the server rejects org/unknown authority (Sol SC9). The
	// node builder refuses to build them; this is the second wall.
	if env.Authority.Authority != dataauthority.AuthorityPersonal {
		s.audit(ctx, p.AccountID, "job_rejected_authority")
		writeErr(w, http.StatusForbidden, "authority_forbidden",
			"only personal-authority evidence is accepted on the personal cloud plane")
		return
	}

	// Two-digest recomputation (Sol SC1): the embedded evidence-content digest
	// must match a recompute over the canonical preimage (tamper check), and the
	// upload digest over the exact bytes must match a confirmed preview receipt.
	recomputedContent, err := cloudcontract.EvidenceContentDigest(env)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "digest recompute failed")
		return
	}
	if env.EvidenceContentDigest == "" || env.EvidenceContentDigest != recomputedContent {
		s.audit(ctx, p.AccountID, "job_rejected_digest_tamper")
		writeErr(w, http.StatusUnprocessableEntity, "digest_mismatch",
			"evidence_content_digest does not match the submitted bytes")
		return
	}
	uploadDigest := cloudcontract.UploadDigest(raw)

	// The upload digest must correspond to a consent receipt (the confirmed
	// literal preview). No matching receipt ⇒ reconfirmation required.
	receiptID, grantedPurposes, receiptGen, err := s.store.ReceiptForDigest(ctx, p.AccountID, uploadDigest)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusConflict, "reconfirmation_required",
			"these exact bytes were not confirmed in a preview; re-run preview-confirmation")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "receipt lookup failed")
		return
	}

	// Out-of-purpose: every field class the envelope populates AND every purpose
	// it declares must be within the receipt's granted purposes.
	if missing, ok := purposesGranted(requiredPurposes(env), grantedPurposes); !ok {
		s.audit(ctx, p.AccountID, "job_rejected_out_of_purpose")
		writeErr(w, http.StatusForbidden, "out_of_purpose",
			"required purpose not granted: "+string(missing))
		return
	}
	for _, dp := range env.DisclosurePurposes {
		if _, ok := purposesGranted([]cloudcontract.Purpose{dp}, grantedPurposes); !ok {
			s.audit(ctx, p.AccountID, "job_rejected_out_of_purpose")
			writeErr(w, http.StatusForbidden, "out_of_purpose",
				"declared disclosure purpose not granted: "+string(dp))
			return
		}
	}

	// Resolve the route once; the server folds route/prompt versions into the
	// canonical key (Sol SC10). The client Idempotency-Key is accepted but is
	// NOT the uniqueness key.
	//
	// The route is a property of the account's PLAN since migration 0039: a paid
	// plan may pin its own route_registry row (Plus -> the Sol deployment) while
	// an unpinned plan resolves the feature default. The plan is read on its own
	// (ResolvePlanForAccount, no entitlements row required) so a missing
	// entitlement still refuses where it always did - inside SubmitJob's
	// reservation - rather than surfacing here as a routing failure.
	plan, err := s.store.ResolvePlanForAccount(ctx, p.AccountID, s.now())
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "no_route", "could not resolve the plan for this account")
		return
	}
	route, fallback, err := s.store.ResolveRouteForPlan(ctx, store.FeatureSessionEnrichment, plan.RouteID)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "no_route", "no active route for this feature")
		return
	}
	if fallback.Fell() {
		// The plan's pinned route cannot serve (not deployed/bound yet, or
		// deactivated) and the job is running on the feature default instead.
		// Never silent: a paid plan quietly served by the cheaper default model
		// is exactly the thing an operator must be able to see.
		s.audit(ctx, p.AccountID, store.PlanRouteFallbackMetric)
		s.log.Warn("cloudserver/api: "+store.PlanRouteFallbackMetric,
			"plan", plan.Name, "plan_version", plan.Version,
			"pinned_route", fallback.RouteID, "reason", fallback.Reason,
			"served_route", route.RouteID)
	}

	// Admission policy check (FA6 / §2.2): verify a FRESH matching attestation and
	// a present credential for THIS exact resolved route BEFORE reserving
	// allowance or storing evidence. An unbound route, stale/unhealthy canary,
	// control-plane outage, or absent credential refuses the job up front — the
	// server never takes custody of user evidence for a job that is already
	// known to be unprocessable. The worker REPEATS (does not reuse) this check
	// under the execution lease.
	//
	// This gate is UNCONDITIONAL and FAIL-CLOSED: a server built without an
	// attestor or credential source (the credential-absent staging posture, or a
	// misconstruction) refuses every job rather than silently storing evidence it
	// can never process. The full auth/PoP/digest path still runs — the request
	// reaches here and gets a clean 503 — so the upload path is exercisable in
	// staging without provisioning a provider. cmd/observer-cloud `serve` wires
	// chooseAttestor + chooseCredentials, so a credential-absent server resolves
	// to AbsentCredentials here and refuses; a provider-enabled one admits.
	if s.attestor == nil || s.credentials == nil {
		s.audit(ctx, p.AccountID, "job_rejected_admission_unwired")
		writeErr(w, http.StatusServiceUnavailable, "provider_policy_unverified",
			"cloud intelligence is not accepting jobs yet")
		return
	}
	if _, ok, cerr := s.credentials.ProviderKey(ctx, route.RouteID); cerr != nil || !ok {
		s.audit(ctx, p.AccountID, "job_rejected_admission_credential")
		writeErr(w, http.StatusServiceUnavailable, "provider_policy_unverified",
			"cloud intelligence is not accepting jobs for this route yet")
		return
	}
	att, aerr := s.attestor.Attest(ctx, route, s.now())
	if aerr != nil || !att.Verified {
		s.audit(ctx, p.AccountID, "job_rejected_admission_attestation")
		writeErr(w, http.StatusServiceUnavailable, "provider_policy_unverified",
			"cloud intelligence is not accepting jobs for this route yet")
		return
	}

	canonical := canonicalJobKey(p.AccountID, env.CloudSessionID, store.FeatureSessionEnrichment,
		env.SchemaVersion, uploadDigest, route.RouteVersion, route.PromptVersion)

	sub, err := s.store.SubmitJob(ctx, store.SubmitJobInput{
		AccountID:         p.AccountID,
		CloudProjectID:    env.CloudProjectID,
		CloudSessionID:    env.CloudSessionID,
		Tool:              env.Tool,
		ModelFamily:       env.ModelFamily,
		Metrics:           sessionMetricsJSON(env),
		Feature:           store.FeatureSessionEnrichment,
		RouteID:           route.RouteID,
		RouteVersion:      route.RouteVersion,
		PromptVersion:     route.PromptVersion,
		CanonicalKey:      canonical,
		ClientIdemKey:     strings.TrimSpace(r.Header.Get("Idempotency-Key")),
		ConsentGeneration: receiptGen,
		ConsentReceiptID:  receiptID,
		UploadDigest:      uploadDigest,
		ContentDigest:     recomputedContent,
		BlobRef:           "evidence/" + env.CloudSessionID + "/" + uploadDigest,
		SizeBytes:         int64(len(raw)),
		EvidenceBytes:     raw, // persisted (encrypted) atomically with the job (plan §6 CI-P4)
		Now:               s.now(),
	})
	if err != nil {
		writeJobSubmitError(w, s.log, err)
		return
	}
	status := http.StatusAccepted
	if sub.Existing {
		status = http.StatusOK
	}
	// "status" is the canonical key (cloudclient.UploadResponse.Status);
	// cloud_session_id lets the node associate the job immediately. "state" is
	// kept as a compatibility alias.
	writeJSON(w, status, map[string]any{
		"job_id":           sub.JobID,
		"status":           sub.State,
		"state":            sub.State,
		"cloud_session_id": env.CloudSessionID,
		"existing":         sub.Existing,
	})
}

func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	j, err := s.store.GetJob(r.Context(), p.AccountID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "job not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not read job")
		return
	}
	writeJSON(w, http.StatusOK, j)
}

func writeJobSubmitError(w http.ResponseWriter, log *slog.Logger, err error) {
	switch {
	case errors.Is(err, store.ErrDailyLimit):
		writeErr(w, http.StatusTooManyRequests, "daily_limit", "daily allowance exhausted")
	case errors.Is(err, store.ErrMonthlyLimit):
		writeErr(w, http.StatusTooManyRequests, "monthly_limit", "monthly allowance exhausted")
	case errors.Is(err, store.ErrConcurrency):
		writeErr(w, http.StatusTooManyRequests, "concurrency_limit", "too many jobs in flight")
	case errors.Is(err, store.ErrGlobalBudget):
		writeErr(w, http.StatusServiceUnavailable, "budget_exhausted", "free-tier budget exhausted")
	case errors.Is(err, store.ErrNoEntitlement):
		writeErr(w, http.StatusForbidden, "no_entitlement", "no entitlement for this feature")
	case errors.Is(err, store.ErrAccountClosed):
		writeErr(w, http.StatusForbidden, "account_closed", "this account is closed or being deleted")
	default:
		// Logged: the client only sees the opaque 500. A silent failure here
		// (2026-09-03 staging: submit 500'd under the sbci_api role on a grant
		// the suite never exercised) is undiagnosable from the outside.
		if log != nil {
			log.Error("cloudserver/api: submit job", "err", err)
		}
		writeErr(w, http.StatusInternalServerError, "internal", "could not submit job")
	}
}

// sessionMetricsJSON builds the content-free structural snapshot captured on
// cloud_sessions at submit time (migration 0037, W5): the envelope's
// MetricsBlock/Outcomes/ActivityMix field names copied verbatim — no
// excerpts, no paths, no action targets, mirroring the envelope's own
// content-free bar. actions_total restores the WHOLE-session action count
// (the bounded Actions sample plus whatever Overflow summarized away), the
// same "cheapest honest answer" ActivityMix already exists to give. A
// marshal failure of this static, already-validated shape is unreachable, so
// the error is discarded (mirrors buildLunaResultSchema's precedent).
func sessionMetricsJSON(env cloudcontract.Envelope) []byte {
	actionsTotal := len(env.Actions)
	if env.Overflow != nil {
		actionsTotal += env.Overflow.ActionsOmitted
	}
	m := map[string]any{
		"duration_seconds":  env.DurationSeconds,
		"started_at_bucket": env.StartedAtBucket,
		"tokens_in":         env.Metrics.TokensIn,
		"tokens_out":        env.Metrics.TokensOut,
		"cache_read":        env.Metrics.CacheReadTokens,
		"cost_usd":          env.Metrics.CostUSD,
		"error_rate":        env.Metrics.ErrorRate,
		"actions_total":     actionsTotal,
		"outcomes":          env.Outcomes,
	}
	if len(env.ActivityMix) > 0 {
		m["activity_mix"] = env.ActivityMix
	}
	b, _ := json.Marshal(m)
	return b
}

// canonicalJobKey derives the server-side idempotency key (Sol SC10): account +
// cloud session + feature + schema + upload digest + resolved route/prompt
// versions. A change in any component (e.g. a different upload digest, or a
// route bump) yields a new job.
func canonicalJobKey(accountID, cloudSessionID, feature, schema, uploadDigest string, routeVer, promptVer int64) string {
	h := sha256.New()
	for _, part := range []string{accountID, cloudSessionID, feature, schema, uploadDigest} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	h.Write([]byte(strconv.FormatInt(routeVer, 10)))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(promptVer, 10)))
	return "cjk:" + hex.EncodeToString(h.Sum(nil))
}
