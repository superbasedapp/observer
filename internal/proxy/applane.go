package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/applane"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// The local app lane (hosted AI gateway plan L7, ruling L-172): the
// `/up/<id>` lanes an app built on this machine points its model client at.
// On such a lane the proxy already runs AI Apps admission, prices the call
// into api_turns and synthesizes an obs trace; this file adds what makes the
// lane an ENFORCING call path:
//
//   - the app identity the SDK sends: X-Superbased-Service reaches admission
//     and the synthesized span, and X-SBO-Request-Id is honoured (the call is
//     recorded under it) and echoed (gap 1 and 4 of the plan's section 1.11);
//   - the hard model allow-list of [proxy.app_lanes] models (gap 6);
//   - stream_options.include_usage on a chat-completions stream to a host
//     known to accept it (gap 5, APPLANE-2);
//   - the budget reservation through the AppLaneGate seam (gap 2): a hold at
//     the call's worst case before it is forwarded, closed at its actual
//     (or kept at the worst case when the usage never arrives).
//
// Every piece is inert on the default provider lanes (Plane B coding agents)
// and on a node with no app lane: the lane exists only once the user adds
// one (decision 8 of L-174). Enforcement is cooperative: the app holds the
// real provider key and could call the provider directly (APPLANE-1).

// AppLaneOptions configures the app-lane hardening. The zero value turns
// every piece off except the request-id and service headers, which are
// plain reads.
type AppLaneOptions struct {
	// Models is the hard model allow-list per lane id ([proxy.app_lanes]
	// models; applane.LanePatterns). nil ⇒ every model is allowed.
	Models map[string][]string
	// IncludeUsage injects stream_options.include_usage on a lane whose
	// upstream host takes it (applane.IncludeUsageHost).
	IncludeUsage bool
	// WorstCaseOutputTokens is the output ceiling a call is reserved at when
	// its body names none (0 ⇒ the config default).
	WorstCaseOutputTokens int
	// Gate is the optional budget reservation. nil ⇒ no reservation.
	Gate AppLaneGate
}

// AppLaneGate is the optional budget reservation of the local app lane.
// Bound at the obs wiring point (cmd/observer/obs_wire_proxy.go), which knows
// the machine's and the org's app caps and reads the recorded app spend, so
// internal/proxy never imports internal/obs (the reverse-import boundary).
// The seam is value-in/value-out; no obs type crosses it.
type AppLaneGate interface {
	// ReserveAppLane decides a lane call before it is forwarded. A refused
	// decision is answered 402 and never forwarded; an admitted one may
	// carry a hold the proxy closes exactly once on every exit path.
	ReserveAppLane(ctx context.Context, in AppLaneReserve) AppLaneDecision
}

// AppLaneReserve is the plain lane call the gate decides.
type AppLaneReserve struct {
	Lane      string
	Provider  string
	Model     string
	User      string
	Service   string
	RequestID string
	// WorstCaseUSD and WorstCaseTokens are the call's worst case: the
	// estimated prompt plus the full output ceiling.
	WorstCaseUSD    float64
	WorstCaseTokens int64
	// Priced is false when the cost engine has no price for Model.
	Priced bool
}

// AppLaneDecision is the gate's answer.
type AppLaneDecision struct {
	// Refused is true when a hard cap refuses the call (enforce mode only).
	Refused bool
	// Reason is the refusal's generic message (it may reach the app's end
	// user; the amounts stay on the operator surfaces).
	Reason string
	// Code is the refusal code ("budget_exceeded", "model_unpriced").
	Code string
	// Hold is the call's reservation; nil ⇒ nothing to close.
	Hold AppLaneHold
}

// AppLaneHold is one reserved lane call. CloseAppLane is called exactly once.
type AppLaneHold interface {
	CloseAppLane(c AppLaneClose)
}

// AppLaneOutcome is how a lane call's hold closes.
type AppLaneOutcome string

// The outcomes.
const (
	// AppLaneSettle books the call's actual cost.
	AppLaneSettle AppLaneOutcome = "settle"
	// AppLaneRelease refunds the hold: the call was never forwarded, or the
	// upstream refused it (a non-2xx answer bills nothing).
	AppLaneRelease AppLaneOutcome = "release"
	// AppLaneUnknown keeps the hold at its worst case: the call ran but its
	// usage never arrived (a cut stream, a provider that omitted it). Never
	// booked at $0 (plan section 3.6, item 8a).
	AppLaneUnknown AppLaneOutcome = "unknown"
)

// AppLaneClose is what the proxy learned about the call.
type AppLaneClose struct {
	Outcome AppLaneOutcome
	USD     float64
	Tokens  int64
	// Recorded is true when the gateway rail will also record the call's
	// spend (an obs sink is wired), so the gate's in-memory book can stop
	// counting it once the store's read catches up.
	Recorded bool
}

// appLaneCodeBudget and appLaneCodeModel are the lane's refusal codes, the
// org AI gateway's spelling (internal/aigateway/gwhttp).
const (
	appLaneCodeBudget = "budget_exceeded"
	appLaneCodeModel  = "model_not_allowed"
	// appLaneCodeExposed refuses an app lane on a listener bound beyond
	// loopback with no client authentication (decision 8: loopback only).
	appLaneCodeExposed = "app_lane_not_loopback"
)

// appLaneExposedMessage is the refusal of an app lane on an exposed
// listener.
const appLaneExposedMessage = "App lanes are served only by a proxy bound to loopback, or with client authentication enforced ([proxy].require_client_auth)."

// appLanesRefusedHere reports whether this listener refuses the /up/<id>
// app lanes: it is bound beyond loopback (Serve) and does not enforce client
// authentication, so anything that can reach it could use every lane, and a
// lane with a loopback upstream would relay the network to that loopback
// service (hosted AI gateway review L6; plan decision 8, loopback only). A
// bare Handler() (in-process, tests) is never exposed.
func (p *Proxy) appLanesRefusedHere() bool {
	return p.listenExposed.Load() && !p.ClientAuthEnforced()
}

// appLaneService reads the app's service name on a lane request ("" off a
// lane, or for an absent or malformed value).
func appLaneService(r *http.Request) string {
	if r == nil || obsUpstreamLane(r) == "" {
		return ""
	}
	return applane.NormalizeService(r.Header.Get(applane.HeaderService))
}

// appLaneRequestID returns the SDK's X-SBO-Request-Id when the request is on
// an app lane (lane != "") and the value is a valid id, else "".
func appLaneRequestID(r *http.Request, lane string) string {
	if lane == "" {
		return ""
	}
	id := strings.TrimSpace(r.Header.Get(applane.HeaderRequestID))
	if !applane.ValidRequestID(id) {
		return ""
	}
	return id
}

// appLaneModelAllowed applies the lane's model allow-list. ok=true when no
// list applies or the model matches.
func (p *Proxy) appLaneModelAllowed(lane, model string) bool {
	pats, has := applane.LanePatterns(p.appLanes.Models, lane)
	if !has {
		return true
	}
	return applane.ModelAllowed(pats, model)
}

// appLaneIncludeUsage reports whether a lane call takes the include_usage
// injection: a chat-completions request (never the Responses API; the
// caller classifies the path) to a host known to accept the field.
func (p *Proxy) appLaneIncludeUsage(upstream *url.URL, chatCompletions bool) bool {
	return p.appLanes.IncludeUsage && upstream != nil && chatCompletions &&
		applane.IncludeUsageHost(upstream.Hostname())
}

// appLaneWorstCase prices a lane call's worst case: the estimated prompt
// (body bytes / 4, the gateway's estimate) plus the full output ceiling (the
// body's max tokens, else the configured default). priced=false when the
// cost engine cannot price the model.
func (p *Proxy) appLaneWorstCase(model string, body []byte) (usd float64, tokens int64, priced bool) {
	in := int64(len(body) / 4)
	if in < 1 {
		in = 1
	}
	out := int64(requestMaxOutputTokens(body))
	if out <= 0 {
		out = int64(p.appLanes.WorstCaseOutputTokens)
		if out <= 0 {
			out = 4096
		}
	}
	tokens = in + out
	if p.cost == nil || model == "" {
		return 0, tokens, false
	}
	usd, priced = p.cost.Compute(model, CostTokens{Input: in, Output: out, At: p.now()})
	return usd, tokens, priced
}

// requestMaxOutputTokens reads the output ceiling a request body names: the
// largest of max_tokens (Anthropic, OpenAI chat), max_completion_tokens
// (OpenAI chat) and max_output_tokens (OpenAI Responses). 0 when none.
func requestMaxOutputTokens(body []byte) int {
	var raw struct {
		MaxTokens           int `json:"max_tokens"`
		MaxCompletionTokens int `json:"max_completion_tokens"`
		MaxOutputTokens     int `json:"max_output_tokens"`
	}
	if len(bytes.TrimSpace(body)) == 0 || json.Unmarshal(body, &raw) != nil {
		return 0
	}
	return max(raw.MaxTokens, raw.MaxCompletionTokens, raw.MaxOutputTokens)
}

// appLaneCloseFor maps a recorded turn to how its hold closes: a non-2xx
// answer releases (nothing billed), a turn with usage settles at its priced
// cost, and a 2xx turn with no usage keeps the worst case.
func appLaneCloseFor(t models.APITurn, status int, recorded bool) AppLaneClose {
	if status < 200 || status >= 300 || (t.HTTPStatus != 0 && (t.HTTPStatus < 200 || t.HTTPStatus >= 300)) {
		return AppLaneClose{Outcome: AppLaneRelease}
	}
	if t.Model == "" || isEmptyUsage(t) {
		return AppLaneClose{Outcome: AppLaneUnknown}
	}
	return AppLaneClose{
		Outcome:  AppLaneSettle,
		USD:      t.CostUSD,
		Tokens:   t.InputTokens + t.OutputTokens + t.CacheReadTokens + t.CacheCreationTokens,
		Recorded: recorded,
	}
}

// writeAppLaneRefusal writes a lane refusal in the provider's error shape,
// with the org AI gateway's code, so a model SDK raises it as an ordinary
// API error and the superbased SDK helpers parse it like a gateway refusal.
func writeAppLaneRefusal(w http.ResponseWriter, provider string, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(appLaneRefusalBody(provider, status, code, msg))
}

// appLaneRefusalBody builds the provider-shaped refusal body.
func appLaneRefusalBody(provider string, status int, code, msg string) []byte {
	var body []byte
	if provider == models.ProviderOpenAI {
		typ := "permission_error"
		if status == http.StatusPaymentRequired {
			typ = "insufficient_quota"
		}
		body, _ = json.Marshal(map[string]any{
			"error": map[string]any{"message": msg, "type": typ, "code": code},
		})
		return body
	}
	typ := "permission_error"
	if status == http.StatusPaymentRequired {
		typ = "billing_error"
	}
	body, _ = json.Marshal(map[string]any{
		"type":  "error",
		"error": map[string]any{"type": typ, "message": msg, "code": code},
	})
	return body
}
