package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// Gateway-Mode fallback-ladder RUNTIME executor (Sol S10 / Luna L16,
// docs/plans/plane-b-dual-mode-gateway-rbac-ia-design-2026-08-29.md §2, and
// docs/plans/plane-b-gateway-implementation-tracker-2026-08-29.md P5b/P6).
//
// P5a/P5b froze the ladder CONTRACT: a Gateway-Mode routing snapshot carries
// an ordered try[] (primary first, then each fallback endpoint) plus exactly
// one terminal rung. This file is the piece that WALKS that contract at
// request time. It is engaged ONLY for a request that resolved to Gateway
// Mode (gatewayRouted, Sol S8) — a build with no org-route installed never
// reaches walkGatewayLadder, so the pre-P5a path is byte-identical
// ("inert-by-default green").
//
// The terminal vocabulary is DUPLICATED from internal/policyfam/providers on
// purpose: internal/proxy is a hot path and must not import policyfam
// (imports discipline — providers already documents the reverse ban). The
// three strings are a closed, stable wire vocabulary, so duplicating them is
// the same trade the codebase already makes for reservedAutoLaneID/autoLaneID.
const (
	terminalHold       = "hold"
	terminalBreakGlass = "break_glass"
	terminalDirect     = "direct"
)

// Fleet-alert reasons (the "raise a fleet alert" signal in the terminal-policy
// contract). One is stamped on every GatewayLadderAlert.
const (
	gatewayLadderQueueAndHold   = "queue_and_hold"
	gatewayLadderBreakGlassHeld = "break_glass_unavailable"
	gatewayLadderDirectFallback = "direct_fallback"
)

// gatewayLadderRetryAfterSeconds is the Retry-After the node returns on a
// hold/break-glass terminal. It tells the AGENT to do the queue-and-hold
// (retry later) rather than the node pinning the client connection open across
// many ladder re-walks — the design's "returns a structured rung/remedy error
// the agent can act on, retries with backoff" split of responsibilities.
const gatewayLadderRetryAfterSeconds = "5"

// GatewayFleetAlerter receives one alert each time the Gateway-Mode fallback
// ladder exhausts every configured endpoint and applies its terminal policy.
// It is the design's "the dashboard raises a fleet alert" seam. Bound at the
// daemon composition point (never imported by internal/proxy directly), the
// same seam pattern as VirtualKeySource / CostComputer. Implementations must
// be safe for concurrent calls and must not block the request path.
type GatewayFleetAlerter interface {
	GatewayLadderAlert(GatewayLadderAlert)
}

// GatewayLadderAlert is one exhaustion event: the terminal rung applied, how
// many endpoints were tried, the routing generation, and the last upstream
// status seen (0 when the last attempt was a transport error). Metadata only —
// no request/response content, matching the gateway's metadata-only audit
// posture.
type GatewayLadderAlert struct {
	Reason         string
	Terminal       string
	EndpointsTried int
	Generation     uint64
	LastStatus     int
	Provider       string
}

// gatewayLadderError is the structured rung/remedy body returned to the agent
// on a fail-closed terminal (hold / break-glass). It is provider-neutral JSON
// wrapped in {"error": …} so an agent that speaks either Anthropic or OpenAI
// error shapes still gets a legible, actionable payload.
type gatewayLadderError struct {
	Type           string `json:"type"`
	Message        string `json:"message"`
	Rung           string `json:"rung"`
	Remedy         string `json:"remedy"`
	EndpointsTried int    `json:"endpoints_tried"`
	Generation     uint64 `json:"generation"`
}

// gatewayLadderCtx bundles everything walkGatewayLadder needs beyond the base
// request that was already built for the primary endpoint. It is assembled at
// the serve() call site from the SAME routing snapshot upstreamForPath
// resolved against (one generation), so the endpoints, terminal rung, and
// generation are always internally consistent.
type gatewayLadderCtx struct {
	// endpoints is the ordered ladder: primary first, then each fallback.
	// Never empty when gatewayRouted is true (SetOrgGatewayRoute rejects a
	// gateway mode with a nil primary).
	endpoints []*url.URL
	// upstreamPath / rawQuery are the request path + (identity-stripped)
	// query joined onto each endpoint's base, exactly like the primary build.
	upstreamPath string
	rawQuery     string
	// terminal is the compiled terminal rung (terminalHold default).
	terminal string
	// custodyAck gates terminalDirect (defence in depth over the compile-side
	// refusal to emit direct without an ack).
	custodyAck bool
	// generation is the routing-snapshot generation, stamped on alerts.
	generation uint64
	// provider is the resolved provider (anthropic/openai/google) — used to
	// pick the direct upstream on a custody-acked direct fallback, and stamped
	// on alerts.
	provider string
	// origAuthorization / origAPIKey / origGoogAPIKey / origAzureAPIKey /
	// origKeyQuery are the developer's ORIGINAL provider credentials in every
	// shape they can arrive (bearer, Anthropic x-api-key, Gemini x-goog-api-key
	// header AND ?key= query param, Azure api-key), captured BEFORE Sol S2
	// auth-substitution stripped them. They are restored ONLY on a custody-acked
	// terminalDirect fallback — the one path where custody deliberately becomes
	// convention (F1).
	origAuthorization string
	origAPIKey        string
	origGoogAPIKey    string
	origAzureAPIKey   string
	origKeyQuery      string
}

// walkGatewayLadder forwards a Gateway-Mode request across the ordered ladder,
// then applies the terminal policy on exhaustion (Luna L16). It returns the
// response to relay to the client plus an error, in the SAME shape
// forwardReliable returns, so the serve() relay/capture path is unchanged —
// including on a fail-closed terminal, where it returns a synthetic structured
// 503 (err == nil) so the turn is still captured (local capture continuity
// through gateway failure).
//
//   - primary + each fallback endpoint is tried in order; the first response
//     that is NOT a fallback trigger (a success, or a definitive 4xx like a
//     402 budget deny the gateway itself returned) is returned immediately —
//     a 4xx is the gateway's real answer, not a reason to try another gateway.
//   - on exhaustion of every endpoint the terminal rung applies:
//     hold          → structured 503 + Retry-After + fleet alert (queue-and-
//     hold: the agent retries, custody preserved);
//     break_glass   → structured 503 naming break-glass + fleet alert (the
//     permission is present but the per-machine credential
//     lease rides the enrolment rail, not this runtime, so
//     with no lease it fails closed exactly like hold);
//     direct        → ONLY when custodyAck: re-forward to the developer's
//     direct provider with their ORIGINAL credential restored
//   - a loud fleet alert (custody becomes convention while
//     active). Without custodyAck it degrades to hold.
func (p *Proxy) walkGatewayLadder(r *http.Request, outReq *http.Request, reqBody, plainBody []byte, chain []string, provider string, shape *requestShape, lc gatewayLadderCtx) (*http.Response, error) {
	if len(lc.endpoints) == 0 {
		// Defensive: gatewayRouted should guarantee a primary. Fall back to a
		// single plain forward rather than crash.
		return p.forwardReliable(r, outReq, reqBody, plainBody, chain, provider, shape)
	}

	// Primary attempt: the outReq is already built for endpoints[0]. Give it
	// the full §R12 treatment (same-target retries + key-pool + model chain).
	resp, err := p.forwardReliable(r, outReq, reqBody, plainBody, chain, provider, shape)
	if !isFallbackTrigger(resp, err) {
		return resp, err
	}

	// Fallback endpoints: alternate GATEWAY destinations, same body. No model
	// rewriting across destinations (nil chain) — a fallback GATEWAY is a
	// different custody boundary, not a different model.
	for i := 1; i < len(lc.endpoints); i++ {
		fbReq, rerr := retargetGatewayRequest(r.Context(), outReq, lc.endpoints[i], lc.upstreamPath, lc.rawQuery, reqBody)
		if rerr != nil {
			break
		}
		drainResponse(resp)
		p.logger.Info("proxy: gateway fallback endpoint", "index", i, "host", lc.endpoints[i].Host)
		resp, err = p.forwardReliable(r, fbReq, reqBody, plainBody, nil, provider, shape)
		if !isFallbackTrigger(resp, err) {
			return resp, err
		}
	}

	// Every endpoint exhausted — apply the terminal rung.
	return p.applyTerminalPolicy(r, outReq, reqBody, provider, shape, lc, resp, err)
}

// applyTerminalPolicy is the exhaustion tail of walkGatewayLadder. resp/err
// hold the last failed attempt (drained here before any synthetic reply).
func (p *Proxy) applyTerminalPolicy(r *http.Request, outReq *http.Request, reqBody []byte, provider string, shape *requestShape, lc gatewayLadderCtx, resp *http.Response, err error) (*http.Response, error) {
	lastStatus := 0
	if err == nil && resp != nil {
		lastStatus = resp.StatusCode
	}
	tried := len(lc.endpoints)

	switch lc.terminal {
	case terminalDirect:
		if lc.custodyAck {
			direct := p.directUpstreamForProvider(provider)
			if direct != nil {
				dReq, rerr := retargetGatewayRequest(r.Context(), outReq, direct, lc.upstreamPath, lc.rawQuery, reqBody)
				if rerr == nil {
					// Custody becomes convention: strip the org virtual key (in
					// every credential shape) and restore the developer's ORIGINAL
					// credential so the direct provider accepts the call. The
					// google shapes (x-goog-api-key header AND the ?key= query
					// param) are restored too — they were stripped from the
					// gateway-bound request (F1), so a direct fallback must put
					// them back.
					for _, h := range gatewayCredentialHeaders {
						dReq.Header.Del(h)
					}
					if lc.origAuthorization != "" {
						dReq.Header.Set("Authorization", lc.origAuthorization)
					}
					if lc.origAPIKey != "" {
						dReq.Header.Set("X-Api-Key", lc.origAPIKey)
					}
					if lc.origGoogAPIKey != "" {
						dReq.Header.Set("X-Goog-Api-Key", lc.origGoogAPIKey)
					}
					if lc.origAzureAPIKey != "" {
						dReq.Header.Set("Api-Key", lc.origAzureAPIKey)
					}
					if lc.origKeyQuery != "" {
						q := dReq.URL.Query()
						q.Set("key", lc.origKeyQuery)
						dReq.URL.RawQuery = q.Encode()
					}
					drainResponse(resp)
					p.fireGatewayAlert(GatewayLadderAlert{
						Reason: gatewayLadderDirectFallback, Terminal: terminalDirect,
						EndpointsTried: tried, Generation: lc.generation,
						LastStatus: lastStatus, Provider: provider,
					})
					p.logger.Warn("proxy: gateway ladder exhausted; custody-acked DIRECT fallback active — the developer credential now reaches the provider directly", "provider", provider, "generation", lc.generation)
					// Served model is unchanged (same body, direct destination),
					// so shape is left as-is.
					return p.doWithRetry(dReq, reqBody)
				}
			}
		}
		// custodyAck false or no direct upstream — degrade to hold (never a
		// silent custody downgrade).
		return p.holdTerminal(resp, lc, provider, lastStatus, tried, terminalDirect)
	case terminalBreakGlass:
		drainResponse(resp)
		p.fireGatewayAlert(GatewayLadderAlert{
			Reason: gatewayLadderBreakGlassHeld, Terminal: terminalBreakGlass,
			EndpointsTried: tried, Generation: lc.generation,
			LastStatus: lastStatus, Provider: provider,
		})
		body := mustJSONError(gatewayLadderError{
			Type:           "gateway_unavailable",
			Message:        "The org AI Gateway and all configured fallbacks are unavailable.",
			Rung:           "terminal:break_glass",
			Remedy:         "Break-glass direct access is permitted by policy but requires a per-machine credential lease from the enrolment rail; none is active on this node. Ask an administrator to issue a break-glass lease, then retry.",
			EndpointsTried: tried, Generation: lc.generation,
		})
		return newJSONResponse(http.StatusServiceUnavailable, body, map[string]string{"Retry-After": gatewayLadderRetryAfterSeconds}), nil
	default:
		return p.holdTerminal(resp, lc, provider, lastStatus, tried, terminalHold)
	}
}

// holdTerminal drains the last attempt, raises the queue-and-hold fleet alert,
// and returns the structured fail-closed 503. Shared by the explicit hold rung
// and the degraded (unacked/undestinable) direct rung.
func (p *Proxy) holdTerminal(resp *http.Response, lc gatewayLadderCtx, provider string, lastStatus, tried int, terminal string) (*http.Response, error) {
	drainResponse(resp)
	p.fireGatewayAlert(GatewayLadderAlert{
		Reason: gatewayLadderQueueAndHold, Terminal: terminal,
		EndpointsTried: tried, Generation: lc.generation,
		LastStatus: lastStatus, Provider: provider,
	})
	body := mustJSONError(gatewayLadderError{
		Type:           "gateway_unavailable",
		Message:        "The org AI Gateway and all configured fallbacks are unavailable.",
		Rung:           "terminal:hold",
		Remedy:         "Requests are held (fail-closed) to preserve custody. Retry after the indicated interval; a fleet alert has been raised so an administrator can restore the gateway.",
		EndpointsTried: tried, Generation: lc.generation,
	})
	return newJSONResponse(http.StatusServiceUnavailable, body, map[string]string{"Retry-After": gatewayLadderRetryAfterSeconds}), nil
}

// fireGatewayAlert logs the exhaustion at Warn and, when a sink is bound,
// delivers the alert. Always logs, so an operator sees the event even with no
// dashboard sink wired.
func (p *Proxy) fireGatewayAlert(a GatewayLadderAlert) {
	p.logger.Warn("proxy: gateway fallback ladder exhausted; terminal policy applied",
		"reason", a.Reason, "terminal", a.Terminal, "endpoints_tried", a.EndpointsTried,
		"generation", a.Generation, "last_status", a.LastStatus, "provider", a.Provider)
	if p.gatewayAlerter != nil {
		p.gatewayAlerter.GatewayLadderAlert(a)
	}
}

// directUpstreamForProvider returns the fixed provider upstream, IGNORING any
// installed org-route — the destination a request would have reached in Node
// Mode. It mirrors upstreamForPath's provider branch (the ChatGPT-JWT channel
// is never gateway-routed, so it is not represented here).
func (p *Proxy) directUpstreamForProvider(provider string) *url.URL {
	switch provider {
	case models.ProviderGoogle:
		return p.geminiURL
	case models.ProviderOpenAI:
		return p.openaiURL
	default:
		return p.anthropicURL
	}
}

// retargetGatewayRequest clones a prepared upstream request onto a different
// endpoint base (a fallback gateway, or the direct provider) with a fresh body
// reader. Headers/method are carried from base; the virtual key the base
// carries rides along unless the caller rewrites it (the direct-fallback path
// does).
func retargetGatewayRequest(ctx context.Context, base *http.Request, endpoint *url.URL, upstreamPath, rawQuery string, body []byte) (*http.Request, error) {
	out := *endpoint
	out.Path = joinPath(endpoint.Path, upstreamPath)
	out.RawQuery = rawQuery
	req, err := http.NewRequestWithContext(ctx, base.Method, out.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header = base.Header.Clone()
	req.Host = endpoint.Host
	req.ContentLength = int64(len(body))
	return req, nil
}

// newJSONResponse builds a synthetic *http.Response the serve() relay path can
// copy to the client exactly like a real upstream response — so a fail-closed
// terminal is captured as a turn (local capture continuity) rather than
// swallowed.
func newJSONResponse(status int, body []byte, extraHeaders map[string]string) *http.Response {
	h := make(http.Header)
	h.Set("Content-Type", "application/json")
	for k, v := range extraHeaders {
		h.Set(k, v)
	}
	return &http.Response{
		StatusCode:    status,
		Status:        http.StatusText(status),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        h,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

// gatewayLadderEndpoints flattens an org-route snapshot into the ordered
// ladder (primary first, then each fallback). Returns nil when no gateway
// primary is installed, so a caller can treat "no ladder" and "empty ladder"
// identically.
func gatewayLadderEndpoints(t *laneTable) []*url.URL {
	if t == nil || t.orgRoute.primary == nil {
		return nil
	}
	out := make([]*url.URL, 0, 1+len(t.orgRoute.fallbacks))
	out = append(out, t.orgRoute.primary)
	out = append(out, t.orgRoute.fallbacks...)
	return out
}

// mustJSONError marshals a gatewayLadderError wrapped in {"error": …}. The
// input is a fixed-shape struct so marshalling never fails; on the impossible
// error a minimal literal is returned.
func mustJSONError(e gatewayLadderError) []byte {
	b, err := json.Marshal(map[string]gatewayLadderError{"error": e})
	if err != nil {
		return []byte(`{"error":{"type":"gateway_unavailable","message":"gateway unavailable"}}`)
	}
	return b
}
