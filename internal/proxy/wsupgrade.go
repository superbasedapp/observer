package proxy

import (
	"net/http"
	"strings"
)

// wsupgrade.go - what the proxy does with a websocket upgrade request
// (post-Agent-Access backlog item 14 follow-up 2).
//
// A websocket upgrade is tunnelled opaquely by serveUpgradePassthrough: the
// proxy never parses the frames, so a model turn carried over the socket
// writes NO api_turns row. For an endpoint that has an HTTP streaming
// equivalent, the least invasive way to keep that turn is to refuse the
// upgrade with 426 Upgrade Required, which a client built for this endpoint
// treats as "use HTTP instead".
//
// Grounding (openai/codex rust-v0.157.1, fetched from
// https://codeload.github.com/openai/codex/tar.gz/refs/tags/rust-v0.157.1):
//
//   - The Responses websocket is `<base_url>/responses` with the scheme
//     swapped to ws/wss (codex-api/src/endpoint/responses_websocket.rs calls
//     provider.websocket_url_for_path("/responses"); codex-api/src/provider.rs).
//   - It is tried only when the provider's `supports_websockets` is true:
//     the built-in `openai` provider sets it true, and `openai_base_url`
//     only overrides that built-in provider's base_url, so the
//     openai_base_url shape (what `observer codex` injects and what
//     `--write-config` writes) opens the websocket first. A custom
//     [model_providers.<id>] - including the `openai-observer` provider
//     `observer init` writes - defaults it to false and goes straight to
//     HTTP (model-provider-info/src/lib.rs).
//   - A handshake answered with 426 is mapped to
//     WebsocketStreamOutcome::FallbackToHttp (core/src/client.rs,
//     `status == StatusCode::UPGRADE_REQUIRED`), which calls
//     try_switch_fallback_transport -> force_http_fallback: websockets are
//     disabled for the rest of the session and the SAME request is sent
//     over HTTP streaming at once, with no retry and no user-visible error.
//     Any other non-101 status is an error that runs the retry budget
//     ("Reconnecting... n/m") before the same fallback - the multi-minute
//     "WebSocket wall" the old force_chatgpt_http knob was added for.
//
// Capability, not identity (CLAUDE.md #3): the rule keys on the endpoint
// the upgrade targets, never on which tool sent it. A Realtime upgrade
// (`/v1/realtime`) has no HTTP equivalent and keeps the passthrough.

// upgradeDecision is what the proxy does with one websocket upgrade.
type upgradeDecision int

const (
	// upgradePassthrough tunnels the upgrade to the upstream (uncaptured).
	upgradePassthrough upgradeDecision = iota
	// upgradeHTTPFallback answers 426 so the client re-sends over HTTP,
	// where the proxy captures (and can compress) the turn.
	upgradeHTTPFallback
	// upgradeRefuseGateway answers 502: the org AI Gateway data plane is
	// HTTP-only and the passthrough would forward the developer's own
	// credentials to it (custody blocker G1).
	upgradeRefuseGateway
)

// upgradeFacts are the request facts the upgrade rules read, resolved at
// the call site so the table itself stays pure.
type upgradeFacts struct {
	// forceChatGPTHTTP is [proxy].force_chatgpt_http.
	forceChatGPTHTTP bool
	// chatGPTTraffic: a chatgpt.com backend path or a ChatGPT-JWT request.
	chatGPTTraffic bool
	// httpEquivalent: the upgrade targets an endpoint with an HTTP streaming
	// equivalent the client falls back to (isResponsesEndpoint).
	httpEquivalent bool
	// gatewayRouted: the request resolved to the org AI Gateway.
	gatewayRouted bool
}

// upgradeRule is one row of the ordered upgrade table.
type upgradeRule struct {
	name     string
	match    func(upgradeFacts) bool
	decision upgradeDecision
}

// upgradeRules is walked top-down; the first match wins (CLAUDE.md #5).
// The HTTP-fallback rows sit ABOVE the gateway refusal: a 426 never dials
// any upstream, so it is custody-safe, and the client's HTTP retry then
// reaches the gateway through the normal (auth-substituting) HTTP path.
var upgradeRules = []upgradeRule{
	{"chatgpt_forced_http", func(f upgradeFacts) bool { return f.forceChatGPTHTTP && f.chatGPTTraffic }, upgradeHTTPFallback},
	{"http_equivalent_endpoint", func(f upgradeFacts) bool { return f.httpEquivalent }, upgradeHTTPFallback},
	{"gateway_http_only", func(f upgradeFacts) bool { return f.gatewayRouted }, upgradeRefuseGateway},
}

// decideUpgrade returns what to do with a websocket upgrade.
func decideUpgrade(f upgradeFacts) (upgradeDecision, string) {
	for _, r := range upgradeRules {
		if r.match(f) {
			return r.decision, r.name
		}
	}
	return upgradePassthrough, "passthrough"
}

// httpEquivalentEndpoints are the final path segments of websocket
// endpoints that have an HTTP streaming equivalent a client falls back to
// on 426. One row per endpoint.
var httpEquivalentEndpoints = []string{
	// OpenAI Responses API websocket (codex `<base_url>/responses`; also the
	// chatgpt.com /backend-api/codex/responses shape).
	"responses",
}

// isResponsesEndpoint reports whether path's final segment is one of
// httpEquivalentEndpoints. Matching the last segment (not a prefix) covers
// every base_url shape: /v1/responses, /backend-api/codex/responses, and a
// custom upstream's /api/v1/responses after the /up/<id> strip.
func isResponsesEndpoint(path string) bool {
	path = strings.TrimRight(path, "/")
	last := path
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		last = path[i+1:]
	}
	for _, seg := range httpEquivalentEndpoints {
		if strings.EqualFold(last, seg) {
			return true
		}
	}
	return false
}

// upgradeFallbackMessage is the 426 body. Codex reads only the status.
const upgradeFallbackMessage = "observer: websocket transport is not captured by the proxy; use the HTTP streaming transport"

// writeUpgradeFallback answers a websocket upgrade with 426 Upgrade
// Required so the client re-sends the request over HTTP.
func writeUpgradeFallback(w http.ResponseWriter) {
	http.Error(w, upgradeFallbackMessage, http.StatusUpgradeRequired)
}
