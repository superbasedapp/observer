package judgeclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// captureJudge runs one Complete against a fake endpoint and returns the
// decoded request body.
func captureJudge(t *testing.T, j func(base string) Client, model string) map[string]any {
	t.Helper()
	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer srv.Close()
	if _, err := j(srv.URL).Complete(context.Background(), model, "judge this"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	return decodeJudgeBody(t, raw)
}

// TestJudgeRequestProfile pins L-02: an OpenAI GPT-5 / o-series judge gets
// max_completion_tokens, no temperature and a reasoning effort (the model
// family's default, or the configured override); a chat model, a routed id
// with a provider prefix and an explicit chat profile keep max_tokens and
// temperature 0. One row per llmwire reasoningFamilies row that changes the
// shape (the table itself is pinned by llmwire's TestResolveShape).
func TestJudgeRequestProfile(t *testing.T) {
	cases := []struct {
		name, profile, effort, model string
		maxTokens                    int
		wantParam                    string
		wantTemp                     bool
		wantEffort                   string
		wantCap                      float64
	}{
		{"gpt-5-nano auto", "", "", "gpt-5-nano", 0, "max_completion_tokens", false, "minimal", 2048},
		{"gpt-5 dated auto", "auto", "", "gpt-5-mini-2025-08-07", 0, "max_completion_tokens", false, "minimal", 2048},
		{"gpt-5.1 auto", "", "", "gpt-5.1", 0, "max_completion_tokens", false, "low", 2048},
		{"o3 auto", "", "", "o3-mini", 0, "max_completion_tokens", false, "low", 2048},
		{"o1-mini auto: no effort", "", "", "o1-mini", 0, "max_completion_tokens", false, "", 2048},
		{"gpt-5-chat alias auto", "", "", "gpt-5-chat-latest", 0, "max_tokens", true, "", 512},
		{"chat model auto", "", "", "gpt-4o-mini", 0, "max_tokens", true, "", 512},
		{"routed id stays chat", "", "", "openai/gpt-5-nano", 0, "max_tokens", true, "", 512},
		{"explicit chat wins", "chat", "", "gpt-5-nano", 0, "max_tokens", true, "", 512},
		{"explicit reasoning, unknown deployment", "reasoning", "", "my-azure-deploy", 0, "max_completion_tokens", false, "", 2048},
		{"effort override", "", "low", "gpt-5-nano", 0, "max_completion_tokens", false, "low", 2048},
		{"configured cap kept", "", "", "gpt-5-nano", 300, "max_completion_tokens", false, "minimal", 300},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := captureJudge(t, func(base string) Client {
				return New(base, "cred").WithTuning(tc.maxTokens, 0).WithRequestProfile(tc.profile, tc.effort)
			}, tc.model)
			other := "max_tokens"
			if tc.wantParam == other {
				other = "max_completion_tokens"
			}
			if got, _ := body[tc.wantParam].(float64); got != tc.wantCap {
				t.Errorf("%s = %v, want %v (body %v)", tc.wantParam, body[tc.wantParam], tc.wantCap, body)
			}
			if _, ok := body[other]; ok {
				t.Errorf("%s sent beside %s: %v", other, tc.wantParam, body)
			}
			if _, ok := body["temperature"]; ok != tc.wantTemp {
				t.Errorf("temperature sent = %v, want %v (body %v)", ok, tc.wantTemp, body)
			}
			if got, _ := body["reasoning_effort"].(string); got != tc.wantEffort {
				t.Errorf("reasoning_effort = %q, want %q", got, tc.wantEffort)
			}
		})
	}
}

// TestUpstreamErrorRejection pins the typed error behind admission's
// judge-error label: a 4xx other than 408/429 is a refusal, everything else
// is not. The message keeps the old "judge: upstream <code>" text.
func TestUpstreamErrorRejection(t *testing.T) {
	for _, tc := range []struct {
		code int
		want bool
	}{{400, true}, {401, true}, {404, true}, {408, false}, {429, false}, {500, false}, {503, false}} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.code)
			_, _ = w.Write([]byte(`{"error":"nope"}`))
		}))
		c := New(srv.URL, "cred")
		c.retries = 0
		_, err := c.Complete(context.Background(), "gpt-5-nano", "x")
		srv.Close()
		var ue *UpstreamError
		if !errors.As(err, &ue) {
			t.Fatalf("%d: error %v is not an UpstreamError", tc.code, err)
		}
		if ue.JudgeRejected() != tc.want {
			t.Errorf("%d: JudgeRejected = %v, want %v", tc.code, ue.JudgeRejected(), tc.want)
		}
		if want := "judge: upstream "; err.Error()[:len(want)] != want {
			t.Errorf("%d: message %q lost its prefix", tc.code, err.Error())
		}
	}
}

// TestDefaultTimeout pins L-20: a loopback judge keeps the 1.5 s admission
// budget, a hosted judge gets a default its first call can meet.
func TestDefaultTimeout(t *testing.T) {
	for _, tc := range []struct {
		base string
		want time.Duration
	}{
		{"http://127.0.0.1:11434/v1", 1500 * time.Millisecond},
		{"http://localhost:11434/v1", 1500 * time.Millisecond},
		{"https://api.openai.com/v1", 8 * time.Second},
		{"", 8 * time.Second},
	} {
		if got := DefaultTimeout(tc.base); got != tc.want {
			t.Errorf("DefaultTimeout(%q) = %v, want %v", tc.base, got, tc.want)
		}
	}
}

// TestJudgeSystemPromptDefersToTheCallersFormat pins the live L-02 re-check
// fix: the shared system prompt keeps {score, rationale} as the default but
// defers to a reply format the user message names (admission's
// {"verdicts":[...]}), so a model that obeys the system message first
// still answers in the caller's shape.
func TestJudgeSystemPromptDefersToTheCallersFormat(t *testing.T) {
	body := captureJudge(t, func(base string) Client { return New(base, "cred") }, "gpt-5-nano")
	msgs, _ := body["messages"].([]any)
	if len(msgs) == 0 {
		t.Fatalf("no messages: %v", body)
	}
	sys, _ := msgs[0].(map[string]any)["content"].(string)
	if !strings.Contains(sys, "When the user message specifies a JSON reply format, use exactly that format") || !strings.Contains(sys, `"score"`) {
		t.Errorf("system prompt = %q: it must defer to the caller's format and keep the score default", sys)
	}
}
