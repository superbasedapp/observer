package aigateway

import (
	"context"
	"encoding/json"
	"strings"
)

// RequestMeta is the handful of fields the gateway reads from an inference
// request body pre-first-byte: the model (for policy + pricing), the output
// cap (for the worst-case reservation), and whether the client asked to
// stream. Nothing else about the body is inspected or retained.
type RequestMeta struct {
	Model     string
	MaxTokens int
	Stream    bool
}

// requestBodyShape is the partial decode target. It covers both provider
// families' spellings of the output cap so the reservation is never priced
// short: Anthropic/OpenAI-chat use max_tokens, newer OpenAI uses
// max_completion_tokens, the Responses API uses max_output_tokens.
type requestBodyShape struct {
	Model               string `json:"model"`
	MaxTokens           int    `json:"max_tokens"`
	MaxCompletionTokens int    `json:"max_completion_tokens"`
	MaxOutputTokens     int    `json:"max_output_tokens"`
	Stream              bool   `json:"stream"`
}

// ParseRequestMeta extracts the pre-first-byte fields from a request body. A
// body that does not parse yields the zero RequestMeta — the caller then falls
// back to policy defaults rather than failing, because a malformed body is the
// upstream's error to report, not the gateway's to guess at.
func ParseRequestMeta(body []byte) RequestMeta {
	var s requestBodyShape
	if err := json.Unmarshal(body, &s); err != nil {
		return RequestMeta{}
	}
	max := s.MaxTokens
	if s.MaxCompletionTokens > max {
		max = s.MaxCompletionTokens
	}
	if s.MaxOutputTokens > max {
		max = s.MaxOutputTokens
	}
	return RequestMeta{Model: s.Model, MaxTokens: max, Stream: s.Stream}
}

// EstimateInputTokens gives a coarse pre-first-byte input-token estimate from
// the request byte length (~4 chars/token). It is used only to price the
// worst-case reservation before the real usage is observed; the settlement
// replaces it with the authoritative count. A floor of 1 avoids a zero-cost
// reservation on a tiny body.
func EstimateInputTokens(bodyLen int) int {
	if bodyLen <= 0 {
		return 1
	}
	n := bodyLen / 4
	if n < 1 {
		n = 1
	}
	return n
}

// outputCapFields are the three provider spellings of the output-token cap,
// in the same order ParseRequestMeta reads them.
var outputCapFields = []string{"max_tokens", "max_completion_tokens", "max_output_tokens"}

// ClampMaxOutputTokens rewrites a request body's output-token cap DOWN to
// effMax so the upstream can never generate more than the gateway's worst-case
// reservation priced for (design §2.4.3, Sol S1 — "never reserve less than it
// could actually spend"). Every output-cap field the body already carries
// (max_tokens / max_completion_tokens / max_output_tokens) is lowered to effMax
// when it exceeds it (or is present but non-numeric); a body that carries NONE
// gets max_tokens ADDED at effMax, so an omitted cap cannot let the upstream
// run to its own (much larger) default. Anthropic requires max_tokens and the
// OpenAI-compatible family universally accepts it on the chat wire, so the
// added field is the same for both kinds (the present-field clamp is
// kind-agnostic regardless). A body that does not parse, or a non-positive
// effMax, is returned unchanged. Re-serialized JSON; key order is not preserved
// (no provider depends on it), matching StampPseudonym.
func ClampMaxOutputTokens(kind ProviderKind, body []byte, effMax int) []byte {
	if effMax <= 0 {
		return body
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil || m == nil {
		return body
	}
	present := false
	for _, field := range outputCapFields {
		raw, ok := m[field]
		if !ok {
			continue
		}
		present = true
		if n, isNum := jsonNumberAsInt(raw); !isNum || n > effMax {
			m[field] = effMax
		}
	}
	if !present {
		m["max_tokens"] = effMax
	}
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}

// jsonNumberAsInt reads an integer out of a decoded JSON value. json.Unmarshal
// into map[string]any decodes numbers as float64; json.Number is handled too in
// case a caller decoded with UseNumber. A non-number yields ok=false.
func jsonNumberAsInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	default:
		return 0, false
	}
}

// StampPseudonym injects the pseudonymous member identity into a request body
// where the provider has a field for it (design §2.4.6, ToS finding 7):
// Anthropic's metadata.user_id and the OpenAI family's safety_identifier. It
// never OVERWRITES a value the client already set, and a body that does not
// parse is returned unchanged (best-effort — the stamp is an abuse-attribution
// aid, not a correctness requirement). The returned bytes are re-serialized
// JSON; key order is not preserved, which no provider depends on.
func StampPseudonym(kind ProviderKind, body []byte, pseudonym string) []byte {
	if pseudonym == "" {
		return body
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil || m == nil {
		return body
	}
	switch kind {
	case KindAnthropic:
		meta, _ := m["metadata"].(map[string]any)
		if meta == nil {
			meta = map[string]any{}
		}
		if _, present := meta["user_id"]; !present {
			meta["user_id"] = pseudonym
			m["metadata"] = meta
		}
	default:
		if _, present := m["safety_identifier"]; !present {
			m["safety_identifier"] = pseudonym
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}

// AdmissionRequest is what the gateway hands the Plane-B judged-admission gate
// (design §4.6; gap register G1-JUDGED-ADM): the extracted user text plus the
// content-free identity the policy may scope on. The gate never sees the raw
// body beyond what ExtractPromptText returns.
type AdmissionRequest struct {
	// Text is the latest user-authored message text (ExtractPromptText).
	Text string
	// UserID / Pseudonym identify the member (the pseudonym is what any judge
	// prompt may carry; the real id never leaves the gateway).
	UserID    string
	Pseudonym string
	Model     string
	Principal Principal
}

// AdmissionVerdict is the gate's plain answer.
type AdmissionVerdict struct {
	// Allowed false ⇒ the gateway refuses the request (403 admission_denied)
	// when the policy enforces; an observe-mode policy reports Allowed=true
	// with Observed set so the audit row still carries the finding.
	Allowed   bool
	Observed  bool
	Reason    string
	Criterion string
}

// AdmissionGate is the request-path seam for Plane-B judged admission. A nil
// gate is today's behavior (no admission step). Implementations run
// deterministic layers first and bound the judge by the policy's latency
// budget; a judge failure is the implementation's call (fail-open with
// Observed, or fail-closed under strict), never a gateway panic.
type AdmissionGate interface {
	Admit(ctx context.Context, r AdmissionRequest) AdmissionVerdict
}

// ExtractPromptText returns the text of the LAST user-role message in an
// OpenAI- or Anthropic-shaped chat body (string content or text content
// blocks), or "" when the body carries none. It is deliberately shallow: the
// admission engine's own prefilter/judge does the reading; this only locates
// what to read.
func ExtractPromptText(body []byte) string {
	var s struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &s); err != nil {
		return ""
	}
	for i := len(s.Messages) - 1; i >= 0; i-- {
		if s.Messages[i].Role != "user" {
			continue
		}
		return contentText(s.Messages[i].Content)
	}
	return ""
}

// contentText flattens a message content field: a JSON string, or an array
// of blocks whose text-bearing members carry "text".
func contentText(raw json.RawMessage) string {
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		return str
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return ""
	}
	var parts []string
	for _, b := range blocks {
		if b.Text != "" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n")
}
