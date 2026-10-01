package proxy

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// errorBody is the shape both Anthropic and OpenAI use for 4xx/5xx
// responses. Anthropic wraps as {type: "error", error: {type, message}};
// OpenAI as {error: {type, message, code}}. Either way the inner
// `error` object carries the class + human message we want to surface.
type errorBody struct {
	Type  string `json:"type"`
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
		Code    string `json:"code"`
	} `json:"error"`
}

// parseErrorBody attempts to decode an Anthropic / OpenAI error
// envelope from a non-2xx response body. Returns ("", "") when the
// body wasn't JSON or didn't match either shape — caller should still
// record the turn with HTTPStatus set so the failure isn't lost.
func parseErrorBody(body []byte) (class, message string) {
	if len(body) == 0 {
		return "", ""
	}
	var env errorBody
	if err := json.Unmarshal(body, &env); err != nil {
		return "", ""
	}
	class = env.Error.Type
	if class == "" {
		// OpenAI sometimes uses `code` as the class instead of `type`.
		class = env.Error.Code
	}
	message = env.Error.Message
	return class, message
}

// extractStreamErrorBody pulls an error JSON out of a captured SSE
// stream. Anthropic's streaming error path is usually:
//
//	event: error
//	data: {"type":"error","error":{"type":"overloaded_error","message":"..."}}
//
// We scan for the first `data: {` line that decodes as an error
// envelope and return that body. Returns nil when the captured bytes
// look like a non-SSE JSON error (caller falls through to direct
// parseErrorBody) or contain nothing recognizable.
func extractStreamErrorBody(captured []byte) []byte {
	if len(captured) == 0 {
		return nil
	}
	// SSE lines are CRLF or LF separated; scan for `data: ` prefixes.
	for _, line := range strings.Split(string(captured), "\n") {
		line = strings.TrimRight(line, "\r")
		const prefix = "data: "
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		data := strings.TrimPrefix(line, prefix)
		if !strings.HasPrefix(data, "{") {
			continue
		}
		// Quick check: must have an `error` key. Avoids accepting normal
		// `message_start` / `content_block_*` events that Anthropic
		// emits before the upstream cuts off mid-stream.
		if !strings.Contains(data, `"error"`) {
			continue
		}
		return []byte(data)
	}
	return nil
}

// extractRequestID pulls the upstream's request id from response
// headers. Anthropic uses `x-request-id`, OpenAI uses `x-request-id`
// too on most paths and `request-id` on legacy. Cloudflare's `cf-ray`
// is a last-resort fallback so users have *something* to grep when
// investigating; it's not joinable to api_turns.request_id but better
// than nothing.
func extractRequestID(h http.Header) string {
	for _, k := range []string{"X-Request-Id", "Request-Id", "X-Request-ID"} {
		if v := h.Get(k); v != "" {
			return v
		}
	}
	if v := h.Get("Cf-Ray"); v != "" {
		return "cf-ray:" + v
	}
	return ""
}

// buildErrorTurn assembles the APITurn record the proxy inserts when
// the upstream returned a non-2xx. Tokens are zero (errors don't
// consume billing tokens — though some providers DO bill for failed
// requests in edge cases; that's not currently captured). The model
// comes from the client's request body when parseable. When the
// upstream rejected the request before any model field could be
// extracted, model stays empty and the store's relaxed validation for
// HTTPStatus != 0 turns lets the row through.
func buildErrorTurn(
	provider string,
	req requestShape,
	respBody []byte,
	respHeaders http.Header,
	statusCode int,
	startedAt time.Time,
	sessionID string,
) models.APITurn {
	class, message := parseErrorBody(respBody)
	requestID := extractRequestID(respHeaders)
	now := time.Now().UTC()
	return models.APITurn{
		SessionID:        sessionID,
		Timestamp:        startedAt,
		Provider:         provider,
		Model:            req.Model,
		RequestID:        requestID,
		MessageCount:     req.MessageCount,
		ToolUseCount:     req.ToolUseCount,
		SystemPromptHash: req.SystemPromptHash,
		HTTPStatus:       statusCode,
		ErrorClass:       class,
		ErrorMessage:     truncateError(message),
		TotalResponseMS:  now.Sub(startedAt).Milliseconds(),
		// Record the fast-tier selection even on a failed turn — the
		// request still carried speed:"fast" (Anthropic) or
		// service_tier:"priority" (OpenAI/Codex). Tokens are zero so cost
		// is unaffected, but keeping the flag consistent across the 2xx and
		// non-2xx paths means an operator filtering "fast turns" sees the
		// rejected ones too (e.g. a 429 on a fast request). No response to
		// read the served tier from, so the request-side value is used.
		Fast:        isFastTurn(req, ""),
		ServiceTier: effectiveTier(req, ""),
	}
}

// truncateError caps an upstream error message at 4 KiB so a verbose
// provider response can't blow up the row size. Real Anthropic /
// OpenAI errors are well under this; the cap is just defensive.
func truncateError(s string) string {
	const max = 4096
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
