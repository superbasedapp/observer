package anthropic

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/inference"
	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// fakeTransport is an in-process http.RoundTripper standing in for the
// Anthropic API: no socket is ever opened. It records every request and
// answers with the scripted status + body.
type fakeTransport struct {
	mu       sync.Mutex
	status   int
	body     string
	err      error
	delay    time.Duration
	requests []*recorded
}

type recorded struct {
	method string
	url    string
	header http.Header
	body   map[string]any
}

func (f *fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	f.mu.Lock()
	f.requests = append(f.requests, &recorded{method: r.Method, url: r.URL.String(), header: r.Header.Clone(), body: body})
	status, respBody, err, delay := f.status, f.body, f.err, f.delay
	f.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}
	if err != nil {
		return nil, err
	}
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}, "Request-Id": []string{"req_test"}},
		Body:       io.NopCloser(strings.NewReader(respBody)),
		Request:    r,
	}, nil
}

func (f *fakeTransport) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

const okBody = `{
  "id": "msg_test", "type": "message", "role": "assistant", "model": "claude-haiku-5-5",
  "content": [
    {"type": "thinking", "thinking": "", "signature": "sig"},
    {"type": "text", "text": "{\"title\":\"t\"}"}
  ],
  "stop_reason": "end_turn", "stop_sequence": null,
  "usage": {"input_tokens": 120, "output_tokens": 45, "cache_read_input_tokens": 3000, "cache_creation_input_tokens": 0}
}`

func baseRequest() inference.Request {
	return inference.Request{
		Endpoint:        "https://api.anthropic.test",
		Deployment:      "claude-haiku-5-5",
		APIVersion:      APIVersion,
		APIKey:          "sk-test-explicit",
		Dialect:         inference.DialectAnthropicMessages,
		System:          "SYSTEM PROMPT",
		User:            "EVIDENCE",
		SchemaName:      "session_enrichment",
		Schema:          json.RawMessage(`{"type":"object","additionalProperties":false,"required":["title"],"properties":{"title":{"type":"string"}}}`),
		MaxOutputTokens: 4096,
		Timeout:         2 * time.Second,
	}
}

func newClient(ft *fakeTransport) *Client {
	return &Client{HTTPClient: &http.Client{Transport: ft}}
}

func TestCompleteWireShapeAndParse(t *testing.T) {
	// Ambient credentials and base URL must be ignored: the call goes to the
	// route's endpoint with the request's key, never the environment's.
	t.Setenv("ANTHROPIC_API_KEY", "sk-ambient-must-not-be-used")
	t.Setenv("ANTHROPIC_BASE_URL", "https://ambient.invalid")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "ambient-token")

	ft := &fakeTransport{body: okBody}
	res, err := newClient(ft).Complete(context.Background(), baseRequest())
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if ft.calls() != 1 {
		t.Fatalf("calls = %d, want exactly 1", ft.calls())
	}
	rq := ft.requests[0]
	if rq.method != http.MethodPost || rq.url != "https://api.anthropic.test/v1/messages" {
		t.Errorf("request = %s %s", rq.method, rq.url)
	}
	if got := rq.header.Get("X-Api-Key"); got != "sk-test-explicit" {
		t.Errorf("x-api-key = %q, want the request's explicit key", got)
	}
	if got := rq.header.Get("Authorization"); got != "" {
		t.Errorf("Authorization header present (%q): an ambient token leaked in", got)
	}
	if got := rq.header.Get("Anthropic-Version"); got != APIVersion {
		t.Errorf("anthropic-version = %q", got)
	}

	b := rq.body
	if b["model"] != "claude-haiku-5-5" {
		t.Errorf("model = %v", b["model"])
	}
	if b["max_tokens"] != float64(4096) {
		t.Errorf("max_tokens = %v", b["max_tokens"])
	}
	for _, forbidden := range []string{"tools", "tool_choice", "temperature", "top_p", "top_k", "thinking", "metadata", "stream", "fallbacks"} {
		if _, ok := b[forbidden]; ok {
			t.Errorf("request carries %q; the call must be bounded and default-sampled: %v", forbidden, b)
		}
	}
	sys, _ := b["system"].([]any)
	if len(sys) != 1 {
		t.Fatalf("system = %v, want one text block", b["system"])
	}
	sb, _ := sys[0].(map[string]any)
	if sb["text"] != "SYSTEM PROMPT" {
		t.Errorf("system text = %v", sb["text"])
	}
	if cc, _ := sb["cache_control"].(map[string]any); cc["type"] != "ephemeral" {
		t.Errorf("system cache_control = %v, want ephemeral", sb["cache_control"])
	}
	msgs, _ := b["messages"].([]any)
	if len(msgs) != 1 {
		t.Fatalf("messages = %v", b["messages"])
	}
	m0, _ := msgs[0].(map[string]any)
	if m0["role"] != "user" || !strings.Contains(mustJSON(t, m0["content"]), "EVIDENCE") {
		t.Errorf("message = %v", m0)
	}
	oc, _ := b["output_config"].(map[string]any)
	if oc["effort"] != "low" {
		t.Errorf("effort = %v", oc["effort"])
	}
	f, _ := oc["format"].(map[string]any)
	if f["type"] != "json_schema" {
		t.Errorf("format.type = %v", f["type"])
	}
	if s, _ := f["schema"].(map[string]any); s["additionalProperties"] != false {
		t.Errorf("format.schema = %v", f["schema"])
	}

	if res.Content != `{"title":"t"}` {
		t.Errorf("content = %q (thinking blocks must be skipped)", res.Content)
	}
	want := inference.Usage{Input: 120, Output: 45, CacheRead: 3000}
	if res.Usage != want {
		t.Errorf("usage = %+v, want %+v", res.Usage, want)
	}
	if res.TokensIn != 3120 || res.TokensOut != 45 {
		t.Errorf("tokens in/out = %d/%d, want 3120/45", res.TokensIn, res.TokensOut)
	}
	if res.Model != "claude-haiku-5-5" || res.FinishReason != "end_turn" {
		t.Errorf("model/finish = %q/%q", res.Model, res.FinishReason)
	}
}

func TestCompleteDefaultsAndOptions(t *testing.T) {
	ft := &fakeTransport{body: okBody}
	req := baseRequest()
	req.Endpoint = ""
	req.Schema = nil
	c := &Client{HTTPClient: &http.Client{Transport: ft}, Effort: "medium", DisablePromptCache: true}
	if _, err := c.Complete(context.Background(), req); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	rq := ft.requests[0]
	if !strings.HasPrefix(rq.url, DefaultBaseURL+"/v1/messages") {
		t.Errorf("url = %s, want the default base", rq.url)
	}
	oc, _ := rq.body["output_config"].(map[string]any)
	if oc["effort"] != "medium" {
		t.Errorf("effort = %v", oc["effort"])
	}
	if _, ok := oc["format"]; ok {
		t.Errorf("format present without a schema: %v", oc)
	}
	sb, _ := rq.body["system"].([]any)[0].(map[string]any)
	if _, ok := sb["cache_control"]; ok {
		t.Errorf("cache_control present with prompt caching disabled")
	}
}

func TestCompleteFinishReasons(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		finish    string
		truncated bool
		refused   bool
	}{
		{"max_tokens", strings.Replace(okBody, `"end_turn"`, `"max_tokens"`, 1), inference.FinishLength, true, false},
		{
			"refusal with category", strings.Replace(okBody, `"stop_reason": "end_turn"`,
				`"stop_reason": "refusal", "stop_details": {"type":"refusal","category":"cyber","explanation":"x"}`, 1),
			"refusal:cyber", false, true,
		},
		{
			"refusal without category", strings.Replace(okBody, `"stop_reason": "end_turn"`, `"stop_reason": "refusal"`, 1),
			"refusal", false, true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := newClient(&fakeTransport{body: c.body}).Complete(context.Background(), baseRequest())
			if err != nil {
				t.Fatalf("Complete: %v", err)
			}
			if res.FinishReason != c.finish || res.Truncated() != c.truncated || res.Refused() != c.refused {
				t.Errorf("finish=%q truncated=%v refused=%v", res.FinishReason, res.Truncated(), res.Refused())
			}
		})
	}
}

func TestCompleteErrorClassificationNoRetry(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		check  func(t *testing.T, err error)
	}{
		{"429 is quota", 429, `{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}`, func(t *testing.T, err error) {
			if !errors.Is(err, inference.ErrQuota) {
				t.Errorf("err = %v, want ErrQuota", err)
			}
		}},
		{"529 overloaded is quota", 529, `{"type":"error","error":{"type":"overloaded_error","message":"busy"}}`, func(t *testing.T, err error) {
			if !errors.Is(err, inference.ErrQuota) {
				t.Errorf("err = %v, want ErrQuota", err)
			}
		}},
		{"400 is a provider error with the body", 400, `{"type":"error","error":{"type":"invalid_request_error","message":"bad schema"}}`, func(t *testing.T, err error) {
			var pe *inference.ProviderError
			if !errors.As(err, &pe) || pe.StatusCode != 400 || !strings.Contains(pe.Body, "bad schema") {
				t.Errorf("err = %v, want ProviderError 400 carrying the body", err)
			}
		}},
		{"500 is a provider error", 500, `{"type":"error","error":{"type":"api_error","message":"boom"}}`, func(t *testing.T, err error) {
			var pe *inference.ProviderError
			if !errors.As(err, &pe) || pe.StatusCode != 500 {
				t.Errorf("err = %v, want ProviderError 500", err)
			}
		}},
		{"401 never echoes the key", 401, `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`, func(t *testing.T, err error) {
			if strings.Contains(err.Error(), "sk-test-explicit") {
				t.Errorf("error text carries the API key: %v", err)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ft := &fakeTransport{status: c.status, body: c.body}
			_, err := newClient(ft).Complete(context.Background(), baseRequest())
			if err == nil {
				t.Fatal("want an error")
			}
			c.check(t, err)
			// The worker owns retries (each preceded by the full lease
			// revalidation): the client must make exactly one call.
			if ft.calls() != 1 {
				t.Errorf("calls = %d, want exactly 1 (no SDK retries)", ft.calls())
			}
		})
	}
}

func TestCompleteTimeoutAndTransport(t *testing.T) {
	ft := &fakeTransport{body: okBody, delay: time.Second}
	req := baseRequest()
	req.Timeout = 50 * time.Millisecond
	_, err := newClient(ft).Complete(context.Background(), req)
	if !errors.Is(err, inference.ErrTimeout) {
		t.Errorf("slow provider err = %v, want ErrTimeout", err)
	}
	if ft.calls() != 1 {
		t.Errorf("calls = %d, want 1", ft.calls())
	}

	ft2 := &fakeTransport{err: errors.New("dial tcp: connection refused")}
	_, err = newClient(ft2).Complete(context.Background(), baseRequest())
	if err == nil || errors.Is(err, inference.ErrTimeout) || !strings.Contains(err.Error(), "transport") {
		t.Errorf("transport err = %v", err)
	}
}

func TestCompleteRefusesBadRequestsWithoutACall(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*inference.Request)
	}{
		{"wrong dialect", func(r *inference.Request) { r.Dialect = inference.DialectChatCompletions }},
		{"no key", func(r *inference.Request) { r.APIKey = "  " }},
		{"no model", func(r *inference.Request) { r.Deployment = "" }},
		{"no cap", func(r *inference.Request) { r.MaxOutputTokens = 0 }},
		{"bad schema", func(r *inference.Request) { r.Schema = json.RawMessage(`{not json`) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ft := &fakeTransport{body: okBody}
			req := baseRequest()
			c.mutate(&req)
			if _, err := newClient(ft).Complete(context.Background(), req); err == nil {
				t.Fatal("want an error")
			}
			if ft.calls() != 0 {
				t.Errorf("calls = %d, want 0", ft.calls())
			}
		})
	}
	ft := &fakeTransport{body: okBody}
	req := baseRequest()
	req.Dialect = inference.DialectResponsesStoreFalse
	if _, err := newClient(ft).Complete(context.Background(), req); !errors.Is(err, inference.ErrUnsupportedDialect) {
		t.Errorf("err = %v, want ErrUnsupportedDialect", err)
	}
}

func TestResourceID(t *testing.T) {
	if got := ResourceID(" claude-haiku-5-5 "); got != "anthropic:messages:claude-haiku-5-5" {
		t.Errorf("ResourceID = %q", got)
	}
}

// TestBoundaryImports pins that this client never reaches SQL or the store:
// it is a leaf provider behind the inference seam.
func TestBoundaryImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "github.com/jackc/pgx/v5"},
		ForbiddenTrees: []string{
			"github.com/marmutapp/superbased-observer/internal/cloudserver/store",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs",
		},
		Reason: "the Anthropic client is a leaf provider behind internal/cloudserver/inference",
	})
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
