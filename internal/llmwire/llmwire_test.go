package llmwire

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func f64(v float64) *float64 { return &v }

func TestEncodeRequest(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		req  Request
		want map[string]any
	}{
		{
			name: "minimal",
			req:  Request{Model: "m", Messages: []Message{{Role: RoleUser, Content: "hi"}}},
			want: map[string]any{"model": "m"},
		},
		{
			name: "default cap param",
			req:  Request{Model: "m", System: "sys", Messages: []Message{{Role: RoleUser, Content: "hi"}}, MaxTokens: 50},
			want: map[string]any{"max_tokens": float64(50)},
		},
		{
			name: "completion cap param",
			req:  Request{Model: "m", System: "s", MaxTokens: 50, MaxTokensParam: ParamMaxCompletionTokens},
			want: map[string]any{"max_completion_tokens": float64(50)},
		},
		{
			name: "temperature and effort",
			req:  Request{Model: "m", System: "s", Temperature: f64(0), ReasoningEffort: "low"},
			want: map[string]any{"temperature": float64(0), "reasoning_effort": "low"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			raw, err := EncodeRequest(c.req)
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			for k, v := range c.want {
				if got[k] != v {
					t.Errorf("%s = %v, want %v (body %s)", k, got[k], v, raw)
				}
			}
			for _, banned := range []string{"tools", "stream", "store", "tool_choice"} {
				if _, ok := got[banned]; ok {
					t.Errorf("body carries %q", banned)
				}
			}
			if c.name == "default cap param" {
				if _, ok := got["max_completion_tokens"]; ok {
					t.Error("default cap must not use max_completion_tokens")
				}
				msgs := got["messages"].([]any)
				if len(msgs) != 2 || msgs[0].(map[string]any)["role"] != RoleSystem {
					t.Errorf("system message must lead: %v", msgs)
				}
			}
		})
	}
}

func TestEncodeRequestSchema(t *testing.T) {
	t.Parallel()
	raw, err := EncodeRequest(Request{
		Model: "m", System: "s", SchemaName: "out",
		Schema: json.RawMessage(`{"type":"object"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		RF struct {
			Type string `json:"type"`
			JS   struct {
				Name   string          `json:"name"`
				Strict bool            `json:"strict"`
				Schema json.RawMessage `json:"schema"`
			} `json:"json_schema"`
		} `json:"response_format"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.RF.Type != "json_schema" || got.RF.JS.Name != "out" || !got.RF.JS.Strict || string(got.RF.JS.Schema) != `{"type":"object"}` {
		t.Errorf("response_format = %+v", got.RF)
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		req  Request
		ok   bool
	}{
		{"ok", Request{Model: "m", System: "s"}, true},
		{"no model", Request{System: "s"}, false},
		{"no content", Request{Model: "m"}, false},
		{"bad role", Request{Model: "m", Messages: []Message{{Role: "tool", Content: "x"}}}, false},
		{"neg cap", Request{Model: "m", System: "s", MaxTokens: -1}, false},
		{"bad param", Request{Model: "m", System: "s", MaxTokensParam: "n"}, false},
		{"bad schema", Request{Model: "m", System: "s", Schema: json.RawMessage(`{`)}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			err := c.req.Validate()
			if (err == nil) != c.ok {
				t.Fatalf("err = %v, want ok=%v", err, c.ok)
			}
			if err != nil && !errors.Is(err, ErrInvalidRequest) {
				t.Errorf("err %v does not wrap ErrInvalidRequest", err)
			}
		})
	}
}

func TestEndpoint(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ in, want string }{
		{"https://example.test/v1", "https://example.test/v1/chat/completions"},
		{"https://example.test/v1/", "https://example.test/v1/chat/completions"},
		// Surrounding whitespace (a pasted base URL) is trimmed.
		{" https://example.test/v1 ", "https://example.test/v1/chat/completions"},
		{"http://127.0.0.1:8000/v1//", "http://127.0.0.1:8000/v1/chat/completions"},
	} {
		if got := Endpoint(c.in); got != c.want {
			t.Errorf("Endpoint(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDecodeResponse(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		body    string
		want    Response
		wantErr error
	}{
		{
			name: "plain",
			body: `{"model":"m","choices":[{"message":{"content":"x"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":4}}`,
			want: Response{Content: "x", Model: "m", FinishReason: "stop", Usage: Usage{PromptTokens: 10, CompletionTokens: 4}},
		},
		{
			name: "no usage",
			body: `{"choices":[{"message":{"content":"x"},"finish_reason":"stop"}]}`,
			want: Response{Content: "x", FinishReason: "stop"},
		},
		{
			name: "length normalized",
			body: `{"choices":[{"message":{"content":""},"finish_reason":"length"}]}`,
			want: Response{FinishReason: FinishLength},
		},
		{
			name: "content filter is a refusal",
			body: `{"choices":[{"message":{"content":""},"finish_reason":"content_filter"}]}`,
			want: Response{FinishReason: "refusal:content_filter"},
		},
		{
			name: "refusal field wins",
			body: `{"choices":[{"message":{"content":"","refusal":"no"},"finish_reason":"stop"}]}`,
			want: Response{FinishReason: FinishRefusal},
		},
		{
			name: "cached and reasoning",
			body: `{"choices":[{"message":{"content":"x"},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":50,"prompt_tokens_details":{"cached_tokens":60},"completion_tokens_details":{"reasoning_tokens":30}}}`,
			want: Response{Content: "x", FinishReason: "stop", Usage: Usage{PromptTokens: 100, CachedPromptTokens: 60, CompletionTokens: 50, ReasoningTokens: 30}},
		},
		{name: "no choices", body: `{"choices":[]}`, wantErr: ErrNoChoices},
		{name: "not json", body: `<html>`, wantErr: ErrDecode},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := DecodeResponse([]byte(c.body))
			if c.wantErr != nil {
				if !errors.Is(err, c.wantErr) {
					t.Fatalf("err = %v, want %v", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestUsageAccounting(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name            string
		u               Usage
		uncached, visib int64
	}{
		{"normal", Usage{PromptTokens: 100, CachedPromptTokens: 60, CompletionTokens: 50, ReasoningTokens: 30}, 40, 20},
		{"no details", Usage{PromptTokens: 100, CompletionTokens: 50}, 100, 50},
		{"over-reported cache", Usage{PromptTokens: 10, CachedPromptTokens: 99, CompletionTokens: 5, ReasoningTokens: 99}, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := c.u.UncachedPromptTokens(); got != c.uncached {
				t.Errorf("uncached = %d, want %d", got, c.uncached)
			}
			if got := c.u.VisibleCompletionTokens(); got != c.visib {
				t.Errorf("visible = %d, want %d", got, c.visib)
			}
		})
	}
}

func TestClassifyStatus(t *testing.T) {
	t.Parallel()
	cases := map[int]ErrorClass{
		429: ClassQuota, 408: ClassTimeout, 504: ClassTimeout,
		401: ClassAuth, 403: ClassAuth, 400: ClassRequest, 404: ClassRequest, 422: ClassRequest,
		500: ClassServer, 502: ClassServer, 503: ClassServer, 302: ClassOther, 100: ClassOther,
	}
	for status, want := range cases {
		if got := ClassifyStatus(status); got != want {
			t.Errorf("ClassifyStatus(%d) = %q, want %q", status, got, want)
		}
	}
	if !errors.Is(ErrorFor(429, nil), ErrQuota) || !errors.Is(ErrorFor(504, nil), ErrTimeout) {
		t.Error("429 must be ErrQuota and 504 ErrTimeout")
	}
	var se *StatusError
	if err := ErrorFor(401, []byte("nope")); !errors.As(err, &se) || se.Class != ClassAuth || se.StatusCode != 401 {
		t.Errorf("401 = %v", err)
	}
}

// TestDialectContract decodes every fixture in testdata: the synthetic ones
// and, once M0.3 records it, the real AI Endpoints response.
func TestDialectContract(t *testing.T) {
	t.Parallel()
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	t.Run("synthetic ok response", func(t *testing.T) {
		t.Parallel()
		got, err := DecodeResponse(read("ai_endpoints_chat_completions.synthetic.json"))
		if err != nil {
			t.Fatal(err)
		}
		want := Response{
			Content:      `{"title":"Fix flaky retry test","summary":"Stabilised a retry test."}`,
			Model:        "gpt-oss-20b",
			FinishReason: "stop",
			Usage:        Usage{PromptTokens: 812, CachedPromptTokens: 512, CompletionTokens: 143, ReasoningTokens: 97},
		}
		if got != want {
			t.Errorf("got %+v, want %+v", got, want)
		}
		if got.Usage.UncachedPromptTokens() != 300 || got.Usage.VisibleCompletionTokens() != 46 {
			t.Errorf("accounting = %d / %d", got.Usage.UncachedPromptTokens(), got.Usage.VisibleCompletionTokens())
		}
	})

	t.Run("synthetic truncated response", func(t *testing.T) {
		t.Parallel()
		got, err := DecodeResponse(read("ai_endpoints_chat_completions_truncated.synthetic.json"))
		if err != nil {
			t.Fatal(err)
		}
		if !got.Truncated() || got.Content != "" || got.Usage.CompletionTokens != 256 {
			t.Errorf("got %+v", got)
		}
	})

	t.Run("recorded response when present", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join("testdata", "ai_endpoints_chat_completions.recorded.json")
		raw, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			t.Skip("no recorded AI Endpoints fixture yet (M0.3)")
		}
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeResponse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got.Usage.PromptTokens <= 0 || got.Usage.CompletionTokens <= 0 || got.FinishReason == "" {
			t.Errorf("recorded response lacks usage or finish reason: %+v", got)
		}
	})
}

func TestClientComplete(t *testing.T) {
	t.Parallel()
	ok, err := os.ReadFile(filepath.Join("testdata", "ai_endpoints_chat_completions.synthetic.json"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		status  int
		body    []byte
		wantErr error
		class   ErrorClass
	}{
		{"ok", 200, ok, nil, ""},
		{"quota", 429, []byte("slow down"), ErrQuota, ""},
		{"gateway timeout", 504, nil, ErrTimeout, ""},
		{"auth", 401, []byte(`{"error":"bad key"}`), nil, ClassAuth},
		{"server", 503, []byte("down"), nil, ClassServer},
		{"garbled 200", 200, []byte("not json"), ErrDecode, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			var gotAuth, gotPath, gotCT string
			var gotBody []byte
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAuth, gotPath, gotCT = r.Header.Get("Authorization"), r.URL.Path, r.Header.Get("Content-Type")
				gotBody, _ = io.ReadAll(r.Body)
				w.WriteHeader(c.status)
				_, _ = w.Write(c.body)
			}))
			defer srv.Close()
			cl, err := NewClient(srv.Client())
			if err != nil {
				t.Fatal(err)
			}
			res, err := cl.Complete(context.Background(), srv.URL+"/v1/", "k-test", Request{Model: "gpt-oss-20b", System: "s", MaxTokens: 10})
			if gotPath != "/v1/chat/completions" || gotAuth != authScheme+"k-test" || gotCT != "application/json" {
				t.Errorf("request path=%q auth=%q ct=%q", gotPath, gotAuth, gotCT)
			}
			if !json.Valid(gotBody) {
				t.Errorf("body not JSON: %s", gotBody)
			}
			switch {
			case c.wantErr != nil:
				if !errors.Is(err, c.wantErr) {
					t.Fatalf("err = %v, want %v", err, c.wantErr)
				}
			case c.class != "":
				var se *StatusError
				if !errors.As(err, &se) || se.Class != c.class {
					t.Fatalf("err = %v, want class %s", err, c.class)
				}
			default:
				if err != nil || res.Usage.PromptTokens != 812 {
					t.Fatalf("res=%+v err=%v", res, err)
				}
			}
		})
	}
}

func TestClientKeylessAndContext(t *testing.T) {
	t.Parallel()
	gotAuth := "unset"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Header["Authorization"]; !ok {
			gotAuth = ""
		} else {
			gotAuth = r.Header.Get("Authorization")
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"x"},"finish_reason":"stop"}]}`))
	}))
	defer srv.Close()
	cl, _ := NewClient(srv.Client())
	if _, err := cl.Complete(context.Background(), srv.URL, "  ", Request{Model: "m", System: "s"}); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "" {
		t.Errorf("keyless call sent Authorization %q", gotAuth)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cl.Complete(ctx, srv.URL, "k", Request{Model: "m", System: "s"}); err == nil {
		t.Error("cancelled context must fail")
	}
	if _, err := cl.Complete(context.Background(), srv.URL, "k", Request{}); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("invalid request err = %v", err)
	}
	if _, err := NewClient(nil); err == nil {
		t.Error("nil http client must be refused")
	}
}
