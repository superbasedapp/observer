// Package foundry is the Azure AI Foundry provider client for the CI-P4
// inference worker (plan §2.3). The ONLY active dialect is chat_completions
// (Azure OpenAI-compatible Chat Completions — stateless by design). The
// responses_store_false dialect is implemented (the request builder FORCES
// store:false and a persistence-indicating response fails the job) but stays
// dark: the route resolver refuses it unless an operator verification record
// exists (enforced by the caller, not here). Every call is bounded, single,
// and non-agentic — no tools, no Batch, no stateful endpoints.
package foundry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Dialect selects the API surface.
type Dialect string

const (
	// DialectChatCompletions is the active stateless Chat Completions dialect.
	DialectChatCompletions Dialect = "chat_completions"
	// DialectResponsesStoreFalse is the Responses API with store:false forced.
	DialectResponsesStoreFalse Dialect = "responses_store_false"
)

// Sentinel errors the executor classifies on.
var (
	// ErrQuota is a provider quota/rate-limit response (HTTP 429).
	ErrQuota = errors.New("foundry: provider quota/rate-limit (429)")
	// ErrTimeout is a provider-call timeout / deadline.
	ErrTimeout = errors.New("foundry: provider call timed out")
	// ErrPersistenceViolation means a responses_store_false call returned a
	// response indicating the prompt/completion WAS persisted — a hard failure
	// (the whole point of store:false is no persistence).
	ErrPersistenceViolation = errors.New("foundry: response indicated persistence (store:false violated)")
	// ErrUnsupportedDialect is an unknown dialect.
	ErrUnsupportedDialect = errors.New("foundry: unsupported dialect")
)

// ProviderError is a non-2xx, non-429 provider HTTP response.
type ProviderError struct {
	StatusCode int
	Body       string
}

func (e *ProviderError) Error() string {
	return fmt.Sprintf("foundry: provider status %d: %s", e.StatusCode, truncate(e.Body, 256))
}

// Request is one bounded structured-output completion. The body is built by
// this package (the caller cannot smuggle store:true — the responses builder
// forces store:false).
type Request struct {
	Endpoint        string // Azure OpenAI base, e.g. https://x.openai.azure.com
	Deployment      string // deployment name, e.g. "luna"
	APIVersion      string // e.g. "2024-10-21"
	APIKey          string // api-key header (from the credential seam)
	Dialect         Dialect
	System          string          // system instruction (evidence-as-data framing)
	User            string          // user message (the delimited evidence)
	SchemaName      string          // json_schema name
	Schema          json.RawMessage // JSON schema for strict structured output
	MaxOutputTokens int
	Timeout         time.Duration
}

// Response is the parsed provider result. Content is the model's JSON text
// (the structured output the caller unmarshals into a result).
type Response struct {
	Content   string
	TokensIn  int64
	TokensOut int64
}

// Provider is the seam the worker's Luna executor calls. AzureClient is the
// real implementation; tests inject a fake or drive AzureClient at an httptest
// server.
type Provider interface {
	Complete(ctx context.Context, req Request) (Response, error)
}

// AzureClient is the HTTP provider client.
type AzureClient struct {
	// HTTPClient is used for the call; nil ⇒ a default whose timeout is taken
	// from the request (or 60s).
	HTTPClient *http.Client
}

var _ Provider = (*AzureClient)(nil)

// Complete dispatches on the dialect. chat_completions is active;
// responses_store_false forces store:false and checks for a persistence signal.
func (c *AzureClient) Complete(ctx context.Context, req Request) (Response, error) {
	switch req.Dialect {
	case DialectChatCompletions, "":
		return c.chatCompletions(ctx, req)
	case DialectResponsesStoreFalse:
		return c.responsesStoreFalse(ctx, req)
	default:
		return Response{}, fmt.Errorf("%w: %q", ErrUnsupportedDialect, req.Dialect)
	}
}

func (c *AzureClient) httpClient(req Request) *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	to := req.Timeout
	if to <= 0 {
		to = 60 * time.Second
	}
	return &http.Client{Timeout: to}
}

// BuildChatCompletionsBody constructs the Chat Completions request body. It is
// exported so a test can assert the exact wire shape (strict json_schema,
// temperature 0, no tools).
func BuildChatCompletionsBody(req Request) map[string]any {
	// gpt-5.x reasoning models (the Luna enrichment deployment) require the modern
	// Chat Completions conventions and reject the legacy ones with HTTP 400:
	//   - the output cap is "max_completion_tokens" ("max_tokens" is refused with
	//     unsupported_parameter);
	//   - "temperature" only accepts the default (1) — a pinned 0 is refused with
	//     unsupported_value, so it is omitted (structure comes from the strict
	//     json_schema below, not from a temperature pin). Both were confirmed
	//     against the live gpt-5.6-luna deployment.
	// "max_completion_tokens" is the forward-compatible param across current Azure
	// OpenAI models, so this shape is not gpt-5-specific gating — it is the modern
	// wire the whole chat lane now speaks.
	body := map[string]any{
		"messages": []map[string]any{
			{"role": "system", "content": req.System},
			{"role": "user", "content": req.User},
		},
		"max_completion_tokens": req.MaxOutputTokens,
	}
	if len(req.Schema) > 0 {
		body["response_format"] = map[string]any{
			"type": "json_schema",
			"json_schema": map[string]any{
				"name":   req.SchemaName,
				"strict": true,
				"schema": req.Schema,
			},
		}
	}
	return body
}

func (c *AzureClient) chatCompletions(ctx context.Context, req Request) (Response, error) {
	url := strings.TrimRight(req.Endpoint, "/") +
		"/openai/deployments/" + req.Deployment + "/chat/completions?api-version=" + req.APIVersion
	raw, err := c.post(ctx, req, url, BuildChatCompletionsBody(req))
	if err != nil {
		return Response{}, err
	}
	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return Response{}, fmt.Errorf("foundry: decode chat response: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return Response{}, errors.New("foundry: chat response had no choices")
	}
	return Response{
		Content:   parsed.Choices[0].Message.Content,
		TokensIn:  parsed.Usage.PromptTokens,
		TokensOut: parsed.Usage.CompletionTokens,
	}, nil
}

// BuildResponsesBody constructs the Responses request body with store:false
// FORCED by the builder (not caller config) — plan §2.3.
func BuildResponsesBody(req Request) map[string]any {
	body := map[string]any{
		"model": req.Deployment,
		"store": false, // FORCED — never caller-controllable.
		"input": []map[string]any{
			{"role": "system", "content": req.System},
			{"role": "user", "content": req.User},
		},
		"max_output_tokens": req.MaxOutputTokens,
	}
	if len(req.Schema) > 0 {
		body["text"] = map[string]any{
			"format": map[string]any{
				"type":   "json_schema",
				"name":   req.SchemaName,
				"strict": true,
				"schema": req.Schema,
			},
		}
	}
	return body
}

func (c *AzureClient) responsesStoreFalse(ctx context.Context, req Request) (Response, error) {
	url := strings.TrimRight(req.Endpoint, "/") + "/openai/responses?api-version=" + req.APIVersion
	raw, err := c.post(ctx, req, url, BuildResponsesBody(req))
	if err != nil {
		return Response{}, err
	}
	// A response indicating persistence fails the job (plan §2.3): the store
	// flag must not come back true, and no persisted-object id may appear.
	if indicatesPersistence(raw) {
		return Response{}, ErrPersistenceViolation
	}
	var parsed struct {
		Output []struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
		OutputText string `json:"output_text"`
		Usage      struct {
			InputTokens  int64 `json:"input_tokens"`
			OutputTokens int64 `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return Response{}, fmt.Errorf("foundry: decode responses response: %w", err)
	}
	content := parsed.OutputText
	if content == "" {
		for _, o := range parsed.Output {
			for _, ct := range o.Content {
				content += ct.Text
			}
		}
	}
	return Response{Content: content, TokensIn: parsed.Usage.InputTokens, TokensOut: parsed.Usage.OutputTokens}, nil
}

// indicatesPersistence reports whether a responses body signals server-side
// persistence despite store:false (store echoed true, or a stored flag set).
func indicatesPersistence(raw []byte) bool {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return false
	}
	if v, ok := m["store"].(bool); ok && v {
		return true
	}
	if v, ok := m["stored"].(bool); ok && v {
		return true
	}
	return false
}

func (c *AzureClient) post(ctx context.Context, req Request, url string, body map[string]any) ([]byte, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("foundry: marshal body: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("foundry: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("api-key", req.APIKey)
	resp, err := c.httpClient(req).Do(httpReq)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			return nil, ErrTimeout
		}
		return nil, fmt.Errorf("foundry: transport: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, ErrQuota
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return nil, &ProviderError{StatusCode: resp.StatusCode, Body: string(raw)}
	}
	return raw, nil
}

func isTimeout(err error) bool {
	var te interface{ Timeout() bool }
	return errors.As(err, &te) && te.Timeout()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// FakeProvider is a scripted Provider for the executor e2e + corpora tests.
type FakeProvider struct {
	// Func, when set, fully controls the response.
	Func func(ctx context.Context, req Request) (Response, error)
	// Response/Err are used when Func is nil.
	Response Response
	Err      error
	// Requests records every request for assertions (e.g. evidence-as-data
	// framing, store:false forcing).
	Requests []Request
}

// Complete returns the scripted response, recording the request.
func (f *FakeProvider) Complete(ctx context.Context, req Request) (Response, error) {
	f.Requests = append(f.Requests, req)
	if f.Func != nil {
		return f.Func(ctx, req)
	}
	return f.Response, f.Err
}

var _ Provider = (*FakeProvider)(nil)
