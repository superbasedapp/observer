package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/promptturn"
)

// Admitter is the optional pre-forward input-admission gate (admission spec
// §6.2 — the SECONDARY seam; the SDK admit() front-door is primary, AD7).
// When non-nil on [Options], the proxy calls it BEFORE forwarding a request
// upstream, passing the resolved provider, the incoming user message, and the
// session id. In enforce mode the gate may block the request, in which case
// the proxy returns a provider-shaped refusal and never forwards; in observe
// mode the gate records the shadow verdict and never blocks.
//
// Bound at the obs wiring point (cmd/observer/obs_wire.go) so internal/proxy
// never imports internal/obs — the reverse-import boundary. nil ⇒ admission
// disabled, zero overhead.
//
// The seam is TWO-PHASE (admission-trace-linkage spec §1). Admit judges the
// request and returns the verdict immediately, but for an ALLOWED verdict on
// the forwarded path it may DEFER persisting its audit row and hand back an
// opaque [AdmitToken] on [AdmitResult.Finalize]. The proxy then calls
// FinalizeAdmission exactly once — via defer, on every exit path — with the
// request id that finally resolved for the turn (the provider-echoed id when
// the upstream supplied one, else the proxy's own). That is the only instant
// at which the trace-id seed is knowable AND the row is not yet hash-locked,
// so the gate can stamp a trace id matching the synthesized gateway trace
// instead of mutating a chained row after the fact.
//
// Blocked verdicts persist inside Admit (nothing is forwarded, so no later id
// can resolve) and return a nil Finalize token.
type Admitter interface {
	Admit(ctx context.Context, in AdmitInput) AdmitResult
	// FinalizeAdmission persists a verdict Admit deferred. token is whatever
	// Admit returned on AdmitResult.Finalize; a nil token is a no-op. It is
	// called at most once per Admit and must be safe to call with a token it
	// does not recognize.
	FinalizeAdmission(ctx context.Context, token AdmitToken, resolvedRequestID string)
}

// AdmitToken is the opaque handle to an admission verdict whose audit row the
// gate deferred. The proxy only carries it back to FinalizeAdmission — it
// never inspects it, so no obs type crosses the reverse-import boundary
// (precedent: AdmitRoute.DecisionID + EgressReporter.ReportEgressRealized, the
// realized-outcome callback shape). nil ⇒ nothing to finalize.
type AdmitToken any

// AdmitInput is the plain request the proxy hands the gate. The proxy owns
// provider-shape knowledge (it already parses these bodies), so the gate
// receives a resolved user message rather than raw bytes — keeping the seam a
// value-in/value-out contract with no obs type leakage.
type AdmitInput struct {
	Provider  string
	Text      string
	SessionID string
	RequestID string
	// User is the end-user identity the app shares on a proxy-routed request
	// (the AdmissionUserHeader integration requirement — org-hosted-app model).
	// Empty ⇒ the per-end-user budget gate is inert; the app-wide policy still
	// applies.
	User string
	// Service is the app's service name the SDK sends on a local app lane
	// (X-Superbased-Service, applane.go; L7 gap 1), so the org's
	// service-scoped app caps bind on the proxy path. Empty off a lane or
	// when the app sent none.
	Service string
	// Model is the pre-mutation top-level request model (topLevelModel),
	// resolved before admit() so the egress layer (design §3.4) matches the
	// model the request carried rather than any downstream Channel-B rewrite.
	// Empty ⇒ model-keyed egress matchers do not fire (fail-open).
	Model string
	// PromptTokensEst is a coarse incoming prompt-size band (body bytes / 4)
	// for egress overload/degrade rules (§3.4 caveat).
	PromptTokensEst int
	// Unaccounted names, as content-free type labels, the user content in the
	// judged turn that no extractor reads (promptturn.AdmissionView: an
	// image, a PDF, a legacy prompt field, an undecoded body). The gate
	// refuses such a request under an enforcing policy and records the
	// shadow finding under an observing one (finding H1, L-180), whatever
	// Text says.
	Unaccounted []string
}

// AdmitRoute is the plain Plane-A egress route contract the gate returns for
// the proxy to apply (design §3.3). All fields are plain scalars — NO obs or
// egress type crosses this boundary, exactly like AdmitResult{Block,...}. nil
// ⇒ no egress route. The gate populates it only in enforce mode (advise mode
// evaluates + logs + records the directive but never emits a route to apply).
type AdmitRoute struct {
	// Action is the resolved verb: route_upstream | route_model | set_effort |
	// deny | none.
	Action string
	// UpstreamID + TargetURL + TargetShape describe a route_upstream target.
	// TargetURL is set only for a KNOWN-valid id; empty otherwise.
	UpstreamID  string
	TargetURL   string
	TargetShape string
	// Model is a route_model same-shape swap; Effort is a set_effort level.
	Model  string
	Effort string
	// RuleName + PolicyHash are for the audit outcome the proxy writes.
	RuleName   string
	PolicyHash string
	// OnUnavailable is the runtime fail posture (fail_open | deny).
	OnUnavailable string
	// MustUseTarget pins the target through retries/fallback — the proxy fails
	// closed if it is unavailable at runtime (§3.6). Accompanies
	// OnUnavailable=deny.
	MustUseTarget bool
	// DecisionID is the obs-side audit row id (0 when not persisted). The proxy
	// carries it back on the realized-outcome callback (EgressReporter) so the
	// audit row records what actually happened on the wire — a plain int, no
	// obs type crosses the boundary.
	DecisionID int64
}

// EgressReporter is the OPTIONAL proxy→obs realized-outcome callback (G22 wave
// 2, design §7). After the proxy applies an enforce-mode egress Route and
// forwards (or refuses), it reports what ACTUALLY happened so the obs audit row
// records the realized outcome rather than mere intent. Bound at the obs wiring
// point (cmd/observer/obs_wire.go) exactly like Admitter, so internal/proxy
// never imports internal/obs. nil ⇒ no callback (zero overhead).
type EgressReporter interface {
	ReportEgressRealized(ctx context.Context, out EgressRealized)
}

// EgressRealized is the plain realized-outcome record the proxy hands the
// reporter. All fields are plain scalars — no obs/egress type crosses the seam.
type EgressRealized struct {
	// DecisionID correlates to the obs_egress_decisions row (AdmitRoute.DecisionID).
	DecisionID int64
	// RequestID is the stable per-request id (soft-join backstop).
	RequestID string
	// Applied is true when the rewritten request actually went to the directed
	// target/model AND got a non-error response.
	Applied bool
	// FailClosed is true when a MustUseTarget locality route was refused because
	// its target was unavailable at runtime (breaker open / dial error).
	FailClosed bool
	// Outcome is a short closed-vocabulary label for the audit view
	// (applied | fail_closed | fallback_open | upstream_error | splice_failed).
	Outcome string
}

// Egress realized-outcome labels (the closed vocabulary recorded on the audit
// row's realized_outcome column).
const (
	egressOutcomeApplied      = "applied"
	egressOutcomeFailClosed   = "fail_closed"
	egressOutcomeFallbackOpen = "fallback_open"
	egressOutcomeUpstreamErr  = "upstream_error"
	egressOutcomeBreakerOpen  = "breaker_open"
	egressOutcomeSpliceFail   = "splice_failed"
)

// reportEgressRealized reports one realized egress outcome through the optional
// EgressReporter seam. It is a no-op when no reporter is bound, the route is nil,
// or the decision was not persisted (DecisionID == 0) — so advise-mode and
// no-obs paths pay nothing.
func (p *Proxy) reportEgressRealized(ctx context.Context, route *AdmitRoute, requestID string, applied, failClosed bool, outcome string) {
	if p.egressReporter == nil || route == nil || route.DecisionID == 0 {
		return
	}
	p.egressReporter.ReportEgressRealized(ctx, EgressRealized{
		DecisionID: route.DecisionID,
		RequestID:  requestID,
		Applied:    applied,
		FailClosed: failClosed,
		Outcome:    outcome,
	})
}

// AdmitResult is the gate's decision. Block is true only in enforce mode on a
// terminal (ask/deny) verdict or an egress deny/invalid-target; Reason/Criterion
// annotate the refusal. Route carries the enforce-mode egress directive to
// apply (nil ⇒ none).
type AdmitResult struct {
	Block     bool
	Reason    string
	Criterion string
	Route     *AdmitRoute
	// Finalize is the opaque deferred-persist handle (see [Admitter]). Non-nil
	// only for a verdict whose audit row the gate held back pending the
	// resolved request id; the proxy hands it to FinalizeAdmission exactly once
	// on the way out. nil ⇒ the gate already persisted (or persists nothing).
	Finalize AdmitToken
}

// admit runs the pre-forward gate on a parsed request body. It returns the
// gate's result and true when the proxy should short-circuit (block); false
// means forward as usual. Safe to call with a nil admitter (returns forward).
//
// requestID is the stable per-request correlation id the proxy establishes
// BEFORE admit (design P0 finding): it is threaded onto the admission/egress
// audit rows so they soft-join to the api_turns row. model is the pre-mutation
// top-level model (topLevelModel), so the egress layer matches the model the
// request actually carried rather than a downstream Channel-B rewrite.
func (p *Proxy) admit(ctx context.Context, provider string, body []byte, userID, service, requestID, model string) (AdmitResult, bool) {
	if p.admitter == nil {
		return AdmitResult{}, false
	}
	view := admissionView(provider, body)
	if view.Empty() {
		// No user content at all (a request with no user turn): nothing to
		// judge, never gated. A tool-result-only turn does not land here:
		// the view judges the prompt that opened the loop (the admission
		// service's verdict cache absorbs the repeat). Content the view
		// cannot read (an image, a document, an undecoded body) is not
		// "nothing": it reaches the gate as Unaccounted (finding H1).
		return AdmitResult{}, false
	}
	text := ""
	if len(view.Units) > 0 {
		text = view.Units[0]
	}
	res := p.admitter.Admit(ctx, AdmitInput{
		Provider:        provider,
		Text:            text,
		SessionID:       sessionIDForProvider(provider, body),
		User:            userID,
		Service:         service,
		RequestID:       requestID,
		Model:           model,
		PromptTokensEst: len(body) / 4,
		Unaccounted:     view.Unaccounted,
	})
	if slices.Contains(view.Unaccounted, promptturn.UnaccountedUnparsed) {
		// An undecoded body (gzip, §3.5) is never routed by egress: the
		// proxy cannot splice what it cannot read. Its admission still ran.
		res.Route = nil
	}
	return res, res.Block
}

// admissionView is the hosted-app admission view of a request body: the
// shared rule (promptturn.AdmissionView, the one owner; the AI gateway's app
// gate calls it too) over the provider lane's wire shape, reading the newest
// user turn.
func admissionView(provider string, body []byte) promptturn.Admission {
	return promptturn.AdmissionView(promptturn.ShapeFor(provider, body), body, promptturn.AdmissionLastTurn)
}

// finalizeAdmission persists a deferred admission verdict through the seam,
// stamping the request id that finally resolved for this turn. It is a no-op
// on a nil admitter or a nil token (a blocked verdict, an admitter that never
// defers, or a request admission never ran on), so the non-obs paths pay
// nothing.
//
// Called from serve() via defer so EVERY exit path — success, upstream error,
// unwinding panic — finalizes exactly once with the best id resolved at that
// point (falling back to the proxy's own request id). The insert context is
// detached (insertTurnDetached precedent): the row must land even when the
// client has already disconnected and cancelled the request context.
func (p *Proxy) finalizeAdmission(handle AdmitToken, resolvedRequestID string) {
	if p.admitter == nil || handle == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p.admitter.FinalizeAdmission(ctx, handle, resolvedRequestID)
}

// resolveEgressTarget parses a Plane-A route's resolved target URL into an
// upstream *url.URL, or nil when it is empty/unparseable (a statically-invalid
// target the obs boundary already blocked in enforce, or a bare advise id that
// never reaches here). The target composes its own path prefix via joinPath at
// build time, exactly like the localUpstreams override.
func (p *Proxy) resolveEgressTarget(route *AdmitRoute) *url.URL {
	if route == nil || route.TargetURL == "" {
		return nil
	}
	u, err := url.Parse(route.TargetURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		p.logger.Warn("proxy: egress target url unparseable; failing per route posture", "url", route.TargetURL, "err", err)
		return nil
	}
	return u
}

// forwardEgressFailOpen re-forwards a request to the pre-egress (default)
// upstream after a fail-open egress target failed at the transport (G22 wave 2,
// §3.6 row 5). It is only reached when NO byte has been streamed to the client
// yet, so a single clean re-forward is safe. It rebuilds the outbound request
// against upstream (composing its own path via joinPath, exactly like the main
// forward) and does one bounded attempt — no fallback chain, since fail-open is
// pure convenience routing.
func (p *Proxy) forwardEgressFailOpen(r *http.Request, upstream *url.URL, upstreamPath string, reqBody []byte) (*http.Response, error) {
	if upstream == nil {
		return nil, http.ErrAbortHandler
	}
	outURL := *upstream
	outURL.Path = joinPath(upstream.Path, upstreamPath)
	outURL.RawQuery = stripHostedIdentityQueryParams(r.URL.RawQuery)
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	p.copyRequestHeaders(outReq.Header, r.Header)
	outReq.Header.Set("Accept-Encoding", "identity")
	outReq.Host = upstream.Host
	outReq.ContentLength = int64(len(reqBody))
	return p.doWithRetry(outReq, reqBody)
}

// admissionUser reads the end-user identity the app shares on a proxy-routed
// request (the AdmissionUserHeader integration requirement — org-hosted-app
// model). An empty header name or an absent header yields "" (the per-end-user
// budget gate is then inert; the app-wide policy still applies).
func (p *Proxy) admissionUser(r *http.Request) string {
	if p.admissionUserHeader == "" {
		return ""
	}
	return strings.TrimSpace(r.Header.Get(p.admissionUserHeader))
}

// writeAdmissionRefusal writes the provider-shaped refusal the proxy returns
// when admission blocks a request in enforce mode. A provider-shaped error
// lets the calling app's SDK surface it as a normal API error rather than a
// malformed response.
func writeAdmissionRefusal(w http.ResponseWriter, provider, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(admissionRefusalBody(provider, reason))
}

// admissionRefusalBody builds the provider-shaped 403 body both admission
// seams (Plane A's hosted-app admitter and Plane B's prompt admitter) return.
func admissionRefusalBody(provider, reason string) []byte {
	if reason == "" {
		reason = "Request blocked by admission policy."
	}
	var body []byte
	if provider == models.ProviderOpenAI {
		body, _ = json.Marshal(map[string]any{
			"error": map[string]any{
				"message": reason,
				"type":    "invalid_request_error",
				"code":    "admission_denied",
			},
		})
	} else {
		// Anthropic-shaped error (the default provider lane).
		body, _ = json.Marshal(map[string]any{
			"type": "error",
			"error": map[string]any{
				"type":    "permission_error",
				"message": reason,
			},
		})
	}
	return body
}

// sessionIDForProvider resolves the session id from a request body using the
// same per-provider extractors the compression path uses.
func sessionIDForProvider(provider string, body []byte) string {
	if provider == models.ProviderOpenAI {
		return extractOpenAISessionID(body)
	}
	return extractAnthropicSessionID(body)
}
