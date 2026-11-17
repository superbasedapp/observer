package llmwire

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// DialectOpenAICompatible names the dialect this package speaks.
const DialectOpenAICompatible = "openai_compatible"

// ChatPath is the path appended to a provider base URL.
const ChatPath = "/chat/completions"

// Roles a Message may carry.
const (
	RoleSystem    = "system"
	RoleUser      = "user"
	RoleAssistant = "assistant"
)

// Message is one chat turn.
type Message struct {
	Role    string
	Content string
}

// Wire field names Request.MaxTokensParam may take.
const (
	ParamMaxTokens           = "max_tokens"
	ParamMaxCompletionTokens = "max_completion_tokens"
)

// Request is one bounded chat completion. Only these fields reach the wire: a
// caller cannot add tools, streaming or persistence flags.
type Request struct {
	// Model is the provider's model id (for example "gpt-oss-20b").
	Model string
	// System is an optional leading system instruction.
	System string
	// Messages are the conversation turns after System.
	Messages []Message
	// MaxTokens caps the completion. On a reasoning model it also covers the
	// reasoning tokens. Zero omits the field (the server default applies).
	MaxTokens int
	// MaxTokensParam names the wire field MaxTokens is sent as: ParamMaxTokens
	// (the default, accepted by OpenAI-compatible servers) or
	// ParamMaxCompletionTokens (what OpenAI's own reasoning models require).
	MaxTokensParam string
	// Temperature is sent only when non-nil (reasoning models often accept
	// only the default).
	Temperature *float64
	// NumCtx is an Ollama-style context-window hint, sent as num_ctx only when
	// positive. Set it only for a loopback model: a hosted OpenAI-compatible
	// API rejects unknown fields.
	NumCtx int
	// ReasoningEffort ("low", "medium", "high") is sent only when non-empty.
	ReasoningEffort string
	// SchemaName and Schema request strict structured output through
	// response_format json_schema. An empty Schema omits response_format.
	SchemaName string
	Schema     json.RawMessage
}

// ErrInvalidRequest wraps every request-validation failure.
var ErrInvalidRequest = errors.New("llmwire: invalid request")

// Validate checks a request before it is encoded.
func (r Request) Validate() error {
	switch {
	case strings.TrimSpace(r.Model) == "":
		return fmt.Errorf("%w: model is required", ErrInvalidRequest)
	case strings.TrimSpace(r.System) == "" && len(r.Messages) == 0:
		return fmt.Errorf("%w: at least one message is required", ErrInvalidRequest)
	case r.NumCtx < 0:
		return fmt.Errorf("%w: num_ctx must not be negative", ErrInvalidRequest)
	case r.MaxTokens < 0:
		return fmt.Errorf("%w: max tokens must not be negative", ErrInvalidRequest)
	case r.MaxTokensParam != "" && r.MaxTokensParam != ParamMaxTokens && r.MaxTokensParam != ParamMaxCompletionTokens:
		return fmt.Errorf("%w: unknown max tokens parameter %q", ErrInvalidRequest, r.MaxTokensParam)
	case len(r.Schema) > 0 && !json.Valid(r.Schema):
		return fmt.Errorf("%w: schema is not valid JSON", ErrInvalidRequest)
	}
	for i, m := range r.Messages {
		if m.Role != RoleSystem && m.Role != RoleUser && m.Role != RoleAssistant {
			return fmt.Errorf("%w: message %d has unknown role %q", ErrInvalidRequest, i, m.Role)
		}
	}
	return nil
}

// Endpoint joins a provider base URL and the chat path, tolerating a trailing
// slash on the base.
func Endpoint(baseURL string) string {
	return strings.TrimRight(strings.TrimSpace(baseURL), "/") + ChatPath
}

type wireMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// EncodeRequest renders the chat-completions JSON body.
func EncodeRequest(r Request) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	msgs := make([]wireMessage, 0, len(r.Messages)+1)
	if s := strings.TrimSpace(r.System); s != "" {
		msgs = append(msgs, wireMessage{Role: RoleSystem, Content: s})
	}
	for _, m := range r.Messages {
		msgs = append(msgs, wireMessage{Role: m.Role, Content: m.Content})
	}
	body := map[string]any{"model": r.Model, "messages": msgs}
	if r.MaxTokens > 0 {
		param := r.MaxTokensParam
		if param == "" {
			param = ParamMaxTokens
		}
		body[param] = r.MaxTokens
	}
	if r.Temperature != nil {
		body["temperature"] = *r.Temperature
	}
	if r.NumCtx > 0 {
		body["num_ctx"] = r.NumCtx
	}
	if r.ReasoningEffort != "" {
		body["reasoning_effort"] = r.ReasoningEffort
	}
	if len(r.Schema) > 0 {
		body["response_format"] = map[string]any{
			"type": "json_schema",
			"json_schema": map[string]any{
				"name":   r.SchemaName,
				"strict": true,
				"schema": r.Schema,
			},
		}
	}
	out, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("llmwire: encode request: %w", err)
	}
	return out, nil
}

// Normalized finish reasons. They match the values the cloud inference seam
// uses, so an adapter can pass them through verbatim.
const (
	// FinishLength means the answer was cut at the token cap.
	FinishLength = "length"
	// FinishRefusal prefixes a provider refusal; a category may follow a colon.
	FinishRefusal = "refusal"
)

// finishTable maps a provider finish_reason onto the normalized vocabulary.
// A reason absent from the table passes through verbatim.
var finishTable = map[string]string{
	"length":         FinishLength,
	"content_filter": FinishRefusal + ":content_filter",
}

// Response is the decoded provider result.
type Response struct {
	// Content is the assistant message text.
	Content string
	// Model is the model id the server reports having served ("" if absent).
	Model string
	// FinishReason is normalized by finishTable; a non-empty message.refusal
	// forces FinishRefusal.
	FinishReason string
	// Usage is the token accounting; zero when the server reported none.
	Usage Usage
}

// Truncated reports whether the answer was cut at the token cap.
func (r Response) Truncated() bool { return r.FinishReason == FinishLength }

// Refused reports whether the provider declined the call.
func (r Response) Refused() bool {
	return r.FinishReason == FinishRefusal || strings.HasPrefix(r.FinishReason, FinishRefusal+":")
}

// Decode errors.
var (
	// ErrDecode wraps a body that is not a chat-completions document.
	ErrDecode = errors.New("llmwire: decode response")
	// ErrNoChoices is a well-formed response with no choices.
	ErrNoChoices = errors.New("llmwire: response had no choices")
)

type wireResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		Message struct {
			Content string `json:"content"`
			Refusal string `json:"refusal"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens        int64 `json:"prompt_tokens"`
		CompletionTokens    int64 `json:"completion_tokens"`
		PromptTokensDetails *struct {
			CachedTokens int64 `json:"cached_tokens"`
		} `json:"prompt_tokens_details"`
		CompletionTokensDetails *struct {
			ReasoningTokens int64 `json:"reasoning_tokens"`
		} `json:"completion_tokens_details"`
	} `json:"usage"`
}

// DecodeResponse parses a 200 chat-completions body. Reasoning text
// (reasoning_content, reasoning) is deliberately never read: only its token
// count matters, and the text is not an output the callers may persist.
func DecodeResponse(raw []byte) (Response, error) {
	var w wireResponse
	if err := json.Unmarshal(raw, &w); err != nil {
		return Response{}, fmt.Errorf("%w: %w", ErrDecode, err)
	}
	if len(w.Choices) == 0 {
		return Response{}, ErrNoChoices
	}
	c := w.Choices[0]
	finish := c.FinishReason
	if n, ok := finishTable[finish]; ok {
		finish = n
	}
	if strings.TrimSpace(c.Message.Refusal) != "" {
		finish = FinishRefusal
	}
	res := Response{Content: c.Message.Content, Model: w.Model, FinishReason: finish}
	if w.Usage != nil {
		res.Usage = Usage{
			PromptTokens:     w.Usage.PromptTokens,
			CompletionTokens: w.Usage.CompletionTokens,
		}
		if d := w.Usage.PromptTokensDetails; d != nil {
			res.Usage.CachedPromptTokens = d.CachedTokens
		}
		if d := w.Usage.CompletionTokensDetails; d != nil {
			res.Usage.ReasoningTokens = d.ReasoningTokens
		}
	}
	return res, nil
}
