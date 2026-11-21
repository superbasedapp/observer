package inference

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
	"time"

	"github.com/marmutapp/superbased-observer/internal/llmwire"
)

func TestOpenAICompatibleComplete(t *testing.T) {
	t.Parallel()
	fixture, err := os.ReadFile(filepath.Join("..", "..", "llmwire", "testdata", "ai_endpoints_chat_completions.synthetic.json"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		status  int
		body    []byte
		wantErr error
		status2 int // expected ProviderError status, 0 = none
		check   func(t *testing.T, r Response)
	}{
		{name: "ok maps usage", status: 200, body: fixture, check: func(t *testing.T, r Response) {
			want := Response{
				Content:   `{"title":"Fix flaky retry test","summary":"Stabilised a retry test."}`,
				TokensIn:  812,
				TokensOut: 143,
				Usage:     Usage{Input: 300, Output: 143, CacheRead: 512},
				Model:     "gpt-oss-20b", FinishReason: "stop",
			}
			if r != want {
				t.Errorf("got %+v, want %+v", r, want)
			}
			if r.Usage.PromptTokens() != 812 {
				t.Errorf("PromptTokens = %d, want 812", r.Usage.PromptTokens())
			}
		}},
		{name: "quota", status: 429, body: []byte("x"), wantErr: ErrQuota},
		{name: "gateway timeout", status: 504, wantErr: ErrTimeout},
		{name: "provider error", status: 401, body: []byte("bad"), status2: 401},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			var gotBody []byte
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotBody, _ = io.ReadAll(r.Body)
				w.WriteHeader(c.status)
				_, _ = w.Write(c.body)
			}))
			defer srv.Close()
			cl, err := llmwire.NewClient(srv.Client())
			if err != nil {
				t.Fatal(err)
			}
			p := &OpenAICompatible{Client: cl}
			res, err := p.Complete(context.Background(), Request{
				Endpoint: srv.URL + "/v1", Deployment: "gpt-oss-20b", APIKey: "k",
				Dialect: DialectOpenAICompatible, System: "sys", User: "usr",
				SchemaName: "out", Schema: json.RawMessage(`{"type":"object"}`),
				MaxOutputTokens: 100, Timeout: 5 * time.Second,
			})
			var sent struct {
				Model    string `json:"model"`
				MaxTok   int    `json:"max_tokens"`
				Messages []struct{ Role, Content string }
			}
			if err := json.Unmarshal(gotBody, &sent); err != nil || sent.Model != "gpt-oss-20b" || sent.MaxTok != 100 || len(sent.Messages) != 2 {
				t.Errorf("sent body = %s (%v)", gotBody, err)
			}
			switch {
			case c.wantErr != nil:
				if !errors.Is(err, c.wantErr) {
					t.Fatalf("err = %v, want %v", err, c.wantErr)
				}
			case c.status2 != 0:
				var pe *ProviderError
				if !errors.As(err, &pe) || pe.StatusCode != c.status2 {
					t.Fatalf("err = %v, want ProviderError %d", err, c.status2)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
				c.check(t, res)
			}
		})
	}
}

func TestOpenAICompatibleRefusals(t *testing.T) {
	t.Parallel()
	var nilP *OpenAICompatible
	if _, err := nilP.Complete(context.Background(), Request{}); err == nil {
		t.Error("nil provider must fail")
	}
	if _, err := (&OpenAICompatible{}).Complete(context.Background(), Request{}); err == nil {
		t.Error("provider without client must fail")
	}
	cl, _ := llmwire.NewClient(http.DefaultClient)
	_, err := (&OpenAICompatible{Client: cl}).Complete(context.Background(), Request{Dialect: DialectAnthropicMessages})
	if !errors.Is(err, ErrUnsupportedDialect) {
		t.Errorf("foreign dialect err = %v", err)
	}
}
