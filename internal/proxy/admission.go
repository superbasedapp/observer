package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
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
	// Model is the pre-mutation top-level request model (topLevelModel),
	// resolved before admit() so the egress layer (design §3.4) matches the
	// model the request carried rather than any downstream Channel-B rewrite.
	// Empty ⇒ model-keyed egress matchers do not fire (fail-open).
	Model string
	// PromptTokensEst is a coarse incoming prompt-size band (body bytes / 4)
	// for egress overload/degrade rules (§3.4 caveat).
	PromptTokensEst int
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
func (p *Proxy) admit(ctx context.Context, provider string, body []byte, userID, requestID, model string) (AdmitResult, bool) {
	if p.admitter == nil {
		return AdmitResult{}, false
	}
	text := extractLastUserText(provider, body)
	if text == "" {
		// Nothing to judge (a tool-result-only turn, or an unparseable
		// body — e.g. an undecoded gzip payload, §3.5) — never gate.
		//
		// G1 visibility fix (docs/audits/multimodal-tracking-audit-2026-08-26.md):
		// this branch also covers an image/audio-only turn, which the judge
		// then silently never evaluates. Judging non-text content is a
		// separate design arc (out of scope here — we must NOT synthesize
		// marker text and feed it to the judge, that would fake coverage).
		// What we CAN do cheaply and safely is tell an admin "there was
		// non-text content here that nothing judged" apart from the
		// routine "truly nothing to judge" case (a tool-result-only turn),
		// by logging a distinct, greppable line — read-only, no Admitter
		// call, so this cannot change gating behavior.
		if types := nonTextBlockTypes(provider, body); len(types) > 0 {
			p.logger.Info(
				"proxy: admission skipped — non-text user content present, not judged",
				"provider", provider,
				"request_id", requestID,
				"session_id", sessionIDForProvider(provider, body),
				"non_text_block_types", types,
			)
		}
		return AdmitResult{}, false
	}
	res := p.admitter.Admit(ctx, AdmitInput{
		Provider:        provider,
		Text:            text,
		SessionID:       sessionIDForProvider(provider, body),
		User:            userID,
		RequestID:       requestID,
		Model:           model,
		PromptTokensEst: len(body) / 4,
	})
	return res, res.Block
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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(body)
}

// sessionIDForProvider resolves the session id from a request body using the
// same per-provider extractors the compression path uses.
func sessionIDForProvider(provider string, body []byte) string {
	if provider == models.ProviderOpenAI {
		return extractOpenAISessionID(body)
	}
	return extractAnthropicSessionID(body)
}

// extractLastUserText returns the text of the LAST user message in a provider
// request body — the "incoming user request" admission gates. Empty when no
// user text is present (a tool-result-only turn or an unparseable body);
// admission treats empty as nothing to judge. Anthropic + OpenAI (chat and
// Responses) shapes are handled; other providers return "" (best-effort).
func extractLastUserText(provider string, body []byte) string {
	if len(body) == 0 {
		return ""
	}
	if provider == models.ProviderOpenAI {
		return lastUserTextOpenAI(body)
	}
	return lastUserTextAnthropic(body)
}

// lastUserTextAnthropic reads the last user message from a Messages API body.
func lastUserTextAnthropic(body []byte) string {
	var raw struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return ""
	}
	for i := len(raw.Messages) - 1; i >= 0; i-- {
		if raw.Messages[i].Role != "user" {
			continue
		}
		if t := decodeMessageText(raw.Messages[i].Content); t != "" {
			return t
		}
	}
	return ""
}

// lastUserTextOpenAI reads the last user message from a Chat Completions
// (messages[]) body, falling back to the Responses API (input string or
// input[] of role/content items).
func lastUserTextOpenAI(body []byte) string {
	var raw struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
		Input json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return ""
	}
	for i := len(raw.Messages) - 1; i >= 0; i-- {
		if raw.Messages[i].Role != "user" {
			continue
		}
		if t := decodeMessageText(raw.Messages[i].Content); t != "" {
			return t
		}
	}
	// Responses API: input is a string, or an array of {role, content} items.
	in := bytes.TrimSpace(raw.Input)
	if len(in) == 0 {
		return ""
	}
	switch in[0] {
	case '"':
		var s string
		if json.Unmarshal(in, &s) == nil {
			return strings.TrimSpace(s)
		}
	case '[':
		var items []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		}
		if json.Unmarshal(in, &items) == nil {
			for i := len(items) - 1; i >= 0; i-- {
				if items[i].Role != "user" {
					continue
				}
				if t := decodeMessageText(items[i].Content); t != "" {
					return t
				}
			}
		}
	}
	return ""
}

// decodeMessageText renders a message content field to plain text. Content is
// either a JSON string or an array of content blocks; any block carrying a
// non-empty "text" field contributes (covers Anthropic text, OpenAI chat
// text, and Responses API input_text). Non-text blocks (images, tool_result)
// are skipped.
func decodeMessageText(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return ""
	}
	if raw[0] == '"' {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return strings.TrimSpace(s)
		}
		return ""
	}
	if raw[0] != '[' {
		return ""
	}
	var blocks []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &blocks) != nil {
		return ""
	}
	var b strings.Builder
	for _, bl := range blocks {
		if bl.Text == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(bl.Text)
	}
	return strings.TrimSpace(b.String())
}

// nonTextBlockTypes returns the distinct content-block "type" values present
// in the LAST user message of a provider request body — companion to
// extractLastUserText, used ONLY for the G1 admission-visibility log line
// (docs/audits/multimodal-tracking-audit-2026-08-26.md): telling "an
// image/audio-only turn the judge never saw" apart from "truly nothing here"
// (a tool-result-only turn) without ever invoking the judge. Best-effort and
// read-only, matching extractLastUserText's own fail-open shape: an
// unparseable or provider-unhandled body, or a message with no array-shaped
// content, yields nil.
func nonTextBlockTypes(provider string, body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	if provider == models.ProviderOpenAI {
		return nonTextBlockTypesOpenAI(body)
	}
	return nonTextBlockTypesAnthropic(body)
}

// nonTextBlockTypesAnthropic finds the last user-role message in a Messages
// API body and reports its non-text block types. Unlike lastUserTextAnthropic
// (which keeps walking backward past a user message that decoded to no text,
// looking for one that did), this stops at the first — i.e. most recent — user
// message: since the caller already knows overall text extraction came up
// empty, the most recent turn is the one relevant to log.
func nonTextBlockTypesAnthropic(body []byte) []string {
	var raw struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}
	for i := len(raw.Messages) - 1; i >= 0; i-- {
		if raw.Messages[i].Role != "user" {
			continue
		}
		return decodeMessageBlockTypes(raw.Messages[i].Content)
	}
	return nil
}

// nonTextBlockTypesOpenAI mirrors nonTextBlockTypesAnthropic for a Chat
// Completions body, falling back to the Responses API input[] shape — the
// same two shapes lastUserTextOpenAI handles.
func nonTextBlockTypesOpenAI(body []byte) []string {
	var raw struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
		Input json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}
	for i := len(raw.Messages) - 1; i >= 0; i-- {
		if raw.Messages[i].Role != "user" {
			continue
		}
		return decodeMessageBlockTypes(raw.Messages[i].Content)
	}
	in := bytes.TrimSpace(raw.Input)
	if len(in) == 0 || in[0] != '[' {
		return nil
	}
	var items []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	if json.Unmarshal(in, &items) != nil {
		return nil
	}
	for i := len(items) - 1; i >= 0; i-- {
		if items[i].Role != "user" {
			continue
		}
		return decodeMessageBlockTypes(items[i].Content)
	}
	return nil
}

// decodeMessageBlockTypes returns the distinct "type" values of content
// blocks in a message's content field that carry genuine non-text USER
// content the judge never sees — image, image_url, input_image, input_audio,
// audio, document, video, file, etc. — the non-text-detecting companion to
// decodeMessageText.
//
// Two categories are deliberately excluded, both to avoid miscounting the
// EXISTING "nothing to judge" case (extractLastUserText's own doc comment:
// "a tool-result-only turn... never gate") as the NEW "non-text content
// existed but was never judged" case this function exists to surface:
//   - text-shaped types (text, input_text, output_text) — decodeMessageText
//     already covers these; this function only runs when that came up empty
//   - non-user-authored control/plumbing types (tool_use, tool_result,
//     thinking, redacted_thinking, server_tool_use, web_search_tool_result,
//     and similar *_tool_result variants) — these appear in "user"-role
//     messages as protocol mechanics (a tool result re-injected, a replayed
//     thinking block), not content a human/app sent for the judge to weigh
//
// A bare-string content field, or blocks carrying no "type", contribute
// nothing — matching decodeMessageText's own best-effort shape: content this
// function can't positively identify as non-text user content is invisible
// here, not miscounted as such.
func decodeMessageBlockTypes(raw json.RawMessage) []string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '[' {
		return nil
	}
	var blocks []struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &blocks) != nil {
		return nil
	}
	seen := make(map[string]bool, len(blocks))
	var types []string
	for _, bl := range blocks {
		switch bl.Type {
		case "", "text", "input_text", "output_text",
			"tool_use", "tool_result", "server_tool_use",
			"thinking", "redacted_thinking":
			continue
		}
		if strings.HasSuffix(bl.Type, "_tool_result") {
			continue
		}
		if seen[bl.Type] {
			continue
		}
		seen[bl.Type] = true
		types = append(types, bl.Type)
	}
	return types
}
