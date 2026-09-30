package proxy

import (
	"net/http"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/requestclass"
)

// Prompt-grouping hint headers (post-Agent-Access backlog item 14).
//
// Some coding-agent clients tell a gateway which USER PROMPT a request
// serves, so every request in one prompt's fan-out (the main turns plus the
// subagent turns that prompt started) carries the same opaque id. The proxy
// records that id on the captured turn (api_turns.prompt_id, migration 139)
// as an exact user-message boundary for the Next-Message Cost Predictor.
//
// The header is FORWARDED UNTOUCHED: copyRequestHeaders strips only
// hop-by-hop headers, X-Session-Id and the hosted-identity set, never an
// x-claude-code-* hint (pinned by TestPromptHintHeadersForwardedUpstream).
//
// Capability, not identity (CLAUDE.md #3): the proxy never asks which tool
// sent the request. A client that sends one of these headers gets its turns
// grouped; a new client with its own spelling is one more row.
var promptIDHeaders = []string{
	// Claude Code 2.1.283+, sent when CLAUDE_CODE_GATEWAY_HINT_HEADERS=1 (off
	// by default for a custom ANTHROPIC_BASE_URL). "Random UUID that
	// identifies the user prompt a request serves." -
	// https://code.claude.com/docs/en/llm-gateway-protocol#gateway-hint-headers
	"X-Claude-Code-Prompt-Id",
}

// maxPromptIDLen bounds a stored prompt id. The documented value is a
// 36-character UUID; the cap leaves room for another client's id format
// without letting a header write an unbounded string into the database.
const maxPromptIDLen = 128

// promptIDFromHeader returns the first well-formed prompt id among
// promptIDHeaders, or "". A value is kept only when it is a short token of
// printable, non-space ASCII - the shape every documented id has - so a
// malformed or oversized header is ignored rather than stored.
func promptIDFromHeader(h http.Header) string {
	for _, name := range promptIDHeaders {
		if v := strings.TrimSpace(h.Get(name)); validPromptID(v) {
			return v
		}
	}
	return ""
}

// validPromptID reports whether v is a non-empty token of at most
// maxPromptIDLen printable ASCII characters with no spaces.
func validPromptID(v string) bool {
	if v == "" || len(v) > maxPromptIDLen {
		return false
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; c <= ' ' || c > '~' {
			return false
		}
	}
	return true
}

// Request-class hint headers (post-Agent-Access backlog item 14 follow-up).
//
// Claude Code 2.1.273+ tells a gateway what KIND of request it is sending
// (x-claude-code-request-class, "Sent on every request" when hint headers
// are on). The proxy records the class on the captured turn
// (api_turns.request_class, migration 144) so spend can be split by what the
// request was for. Same capability rule as promptIDHeaders: a header-name
// table, never a tool branch; forwarded upstream untouched.
var requestClassHeaders = []string{
	// https://code.claude.com/docs/en/llm-gateway-protocol#gateway-hint-headers
	"X-Claude-Code-Request-Class",
}

// The CLOSED vocabulary a stored request class may take lives in
// internal/requestclass (the one owner, shared with the org ingest's
// re-validation and both dashboards' spend split): exactly the values the
// vendor documents (grounded 2026-09-28 against the gateway-hint-headers
// table). A value outside it - a future class, a different casing, a
// malformed header - is stored as NULL rather than mapped to the nearest
// known class: unknown means unknown.

// requestClassFromHeader returns the stored request class for the first
// request-class header whose (trimmed) value is in requestclass.Values,
// or "" when none is. Matching is exact: the documented values are
// lowercase ASCII and a near-miss is not guessed at.
func requestClassFromHeader(h http.Header) string {
	for _, name := range requestClassHeaders {
		if v := requestclass.Normalize(h.Get(name)); v != "" {
			return v
		}
	}
	return ""
}
