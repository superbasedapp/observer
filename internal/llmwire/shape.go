package llmwire

import (
	"encoding/json"
	"strings"
)

// Request profiles: how a chat-completions request is shaped on the wire. The
// profile is a capability of the model, resolved once at a caller's boundary
// (from its own configured request_profile, or, on auto, from the model id by
// the reasoningFamilies table). Nothing past the resolved Shape branches on a
// provider or a model name (CLAUDE.md rule 3). This file is the one owner of
// the model-family table; internal/judgeclient (the node's judges) and
// internal/orgserver/llmprovider (the org server's providers) both read it.
const (
	// ProfileAuto resolves the profile from the model id (the default).
	ProfileAuto = "auto"
	// ProfileChat sends max_tokens and lets the caller send a temperature:
	// what every OpenAI-compatible chat model and local server accepts.
	ProfileChat = "chat"
	// ProfileReasoning sends max_completion_tokens, no temperature and a
	// reasoning effort: what OpenAI's GPT-5 and o-series models require (they
	// refuse max_tokens and any temperature but the default).
	ProfileReasoning = "reasoning"
)

// Profiles lists the request_profile values, the default first.
func Profiles() []string { return []string{ProfileAuto, ProfileChat, ProfileReasoning} }

// NormalizeProfile lowercases and trims a configured request_profile, maps ""
// to ProfileAuto, and reports whether the value is one of Profiles.
func NormalizeProfile(p string) (string, bool) {
	p = strings.ToLower(strings.TrimSpace(p))
	if p == "" {
		return ProfileAuto, true
	}
	for _, known := range Profiles() {
		if p == known {
			return p, true
		}
	}
	return p, false
}

// ValidProfile reports whether p is a request_profile value a caller's config
// accepts ("" means auto).
func ValidProfile(p string) bool {
	_, ok := NormalizeProfile(p)
	return ok
}

// ReasoningMinReplyTokens is the smallest reply cap a reasoning-profile
// request should carry. On a reasoning model the cap also covers the hidden
// reasoning tokens, so a small cap (a chat default of 512, or a connectivity
// probe's 16) can be spent before any visible text is written; 2048 leaves
// room at a low effort. Callers apply it with Shape.RaiseReplyCap, under
// their own rule for a cap the operator configured.
const ReasoningMinReplyTokens = 2048

// familyRule is one row of the auto-profile table: a bare model id starting
// with prefix gets profile, and (for the reasoning profile) effort as its
// default reasoning effort ("" sends none).
type familyRule struct {
	prefix  string
	profile string
	effort  string
}

// reasoningFamilies is walked top-down; the first matching prefix wins, so a
// more specific prefix sits above a shorter one. It matches a BARE model id
// (as OpenAI's own API takes it, and as an Azure deployment is usually
// named). A routed id with a provider prefix ("openai/gpt-5-nano" on
// OpenRouter or a LiteLLM proxy) is left on the chat profile: those services
// translate max_tokens and drop an unsupported temperature themselves. A
// model this table does not know is set with request_profile = "reasoning"
// (for example an Azure deployment named after a team, not a model). A model
// absent from the table (gpt-4o-mini, gpt-oss-20b, any local model) is chat.
var reasoningFamilies = []familyRule{
	{prefix: "gpt-5-chat", profile: ProfileChat},                    // the non-reasoning GPT-5 chat alias
	{prefix: "gpt-5.", profile: ProfileReasoning, effort: "low"},    // gpt-5.1 and later: no "minimal"
	{prefix: "gpt-5", profile: ProfileReasoning, effort: "minimal"}, // gpt-5, -mini, -nano
	{prefix: "o1-mini", profile: ProfileReasoning},                  // takes no reasoning_effort
	{prefix: "o1-preview", profile: ProfileReasoning},               // takes no reasoning_effort
	{prefix: "o1", profile: ProfileReasoning, effort: "low"},
	{prefix: "o3", profile: ProfileReasoning, effort: "low"},
	{prefix: "o4", profile: ProfileReasoning, effort: "low"},
}

// Shape is the resolved wire shape for one request.
type Shape struct {
	// Profile is the resolved profile: ProfileChat or ProfileReasoning, never
	// ProfileAuto.
	Profile string
	// MaxTokensParam is the wire field the reply cap is sent as.
	MaxTokensParam string
	// TemperatureOff drops any temperature the caller set.
	TemperatureOff bool
	// MinReplyTokens is the smallest reply cap the shape needs (0 = none).
	MinReplyTokens int
	// ReasoningEffort is sent as reasoning_effort when non-empty.
	ReasoningEffort string
}

// ResolveShape resolves a configured profile (and an optional effort
// override) against a model id into the wire shape. An unknown profile is
// treated as auto. The effort override is used only on the reasoning
// profile; an explicit reasoning profile takes no family default effort (the
// model may be one that refuses reasoning_effort). Pure.
func ResolveShape(profile, effort, model string) Shape {
	p, ok := NormalizeProfile(profile)
	if !ok {
		p = ProfileAuto
	}
	defEffort := ""
	if p == ProfileAuto {
		p = ProfileChat
		id := strings.ToLower(strings.TrimSpace(model))
		if !strings.Contains(id, "/") {
			for _, r := range reasoningFamilies {
				if strings.HasPrefix(id, r.prefix) {
					p, defEffort = r.profile, r.effort
					break
				}
			}
		}
	}
	if p != ProfileReasoning {
		return Shape{Profile: ProfileChat, MaxTokensParam: ParamMaxTokens}
	}
	if e := strings.TrimSpace(effort); e != "" {
		defEffort = e
	}
	return Shape{
		Profile:         ProfileReasoning,
		MaxTokensParam:  ParamMaxCompletionTokens,
		TemperatureOff:  true,
		MinReplyTokens:  ReasoningMinReplyTokens,
		ReasoningEffort: defEffort,
	}
}

// Apply returns r in this shape: the reply cap's field name, no temperature
// when the shape turns it off, and the shape's reasoning effort when r names
// none. It leaves r.MaxTokens alone: whether a configured cap may be raised
// to MinReplyTokens is the caller's rule (RaiseReplyCap).
func (s Shape) Apply(r Request) Request {
	if s.MaxTokensParam != "" {
		r.MaxTokensParam = s.MaxTokensParam
	}
	if s.TemperatureOff {
		r.Temperature = nil
	}
	if r.ReasoningEffort == "" {
		r.ReasoningEffort = s.ReasoningEffort
	}
	return r
}

// RaiseReplyCap returns n raised to the shape's MinReplyTokens. A cap of zero
// or less (the server default applies) is returned unchanged.
func (s Shape) RaiseReplyCap(n int) int {
	if n > 0 && n < s.MinReplyTokens {
		return s.MinReplyTokens
	}
	return n
}

// ErrorDoc is the machine-readable part of an OpenAI-shaped error document:
// {"error": {"message", "type", "param", "code"}}.
type ErrorDoc struct {
	Type  string
	Param string
	Code  string
}

// ParseErrorDoc reads the error envelope from a provider's error body. ok is
// false for a body that is not that envelope.
func ParseErrorDoc(body string) (ErrorDoc, bool) {
	var w struct {
		Error *struct {
			Type  string          `json:"type"`
			Param json.RawMessage `json:"param"`
			Code  json.RawMessage `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &w); err != nil || w.Error == nil {
		return ErrorDoc{}, false
	}
	return ErrorDoc{Type: w.Error.Type, Param: jsonString(w.Error.Param), Code: jsonString(w.Error.Code)}, true
}

// jsonString reads a JSON string value; null, a number or anything else is "".
func jsonString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// statusBadRequest is HTTP 400, spelled out so this pure file imports no
// net/http.
const statusBadRequest = 400

// shapeCorrection is one row of the self-correction table: a 400 refusal
// whose error document names this type, param and code says the request was
// sent in the wrong shape, and profile is the shape that model needs.
type shapeCorrection struct {
	errType string
	param   string
	code    string
	profile string
}

// shapeCorrections is keyed on the provider's own error fields, never on a
// model name: a model the family table does not know reveals its shape by
// what it refuses. Walked top-down; the first matching row wins.
var shapeCorrections = []shapeCorrection{
	// "Unsupported parameter: 'max_tokens' is not supported with this model.
	// Use 'max_completion_tokens' instead." (GPT-5, o-series)
	{errType: "invalid_request_error", param: ParamMaxTokens, code: "unsupported_parameter", profile: ProfileReasoning},
	// "Unsupported value: 'temperature' does not support 0 with this model.
	// Only the default (1) value is supported."
	{errType: "invalid_request_error", param: "temperature", code: "unsupported_value", profile: ProfileReasoning},
	// "Unsupported parameter: 'temperature' is not supported with this model."
	{errType: "invalid_request_error", param: "temperature", code: "unsupported_parameter", profile: ProfileReasoning},
	// The reverse: a chat model (or an older OpenAI-compatible server) that
	// does not know max_completion_tokens.
	{errType: "invalid_request_error", param: ParamMaxCompletionTokens, code: "unsupported_parameter", profile: ProfileChat},
}

// CorrectedProfile reads a refused request's status and error body and
// returns the profile to retry it with: a 400 whose error document matches a
// shapeCorrections row. ok is false for any other failure, and when the
// correction is the profile that was already sent (sent), so a caller can
// never loop between two shapes.
func CorrectedProfile(status int, body, sent string) (string, bool) {
	if status != statusBadRequest {
		return "", false
	}
	doc, ok := ParseErrorDoc(body)
	if !ok {
		return "", false
	}
	for _, r := range shapeCorrections {
		if doc.Type == r.errType && doc.Param == r.param && doc.Code == r.code {
			if r.profile == sent {
				return "", false
			}
			return r.profile, true
		}
	}
	return "", false
}
