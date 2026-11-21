package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type fakePromptAdmitter struct {
	mu       sync.Mutex
	block    bool
	inactive bool
	calls    []PromptAdmitInput
}

func (f *fakePromptAdmitter) PromptAdmissionActive() bool { return !f.inactive }

func (f *fakePromptAdmitter) AdmitPrompt(_ context.Context, in PromptAdmitInput) PromptAdmitResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, in)
	if f.block {
		return PromptAdmitResult{Block: true, Reason: "not allowed here", Criterion: "c1"}
	}
	return PromptAdmitResult{}
}

// TestPromptAdmitterSeam is one row per lane x verdict (P-228): the Plane-B
// prompt admitter runs on the default provider lanes only, sees the
// pre-compression body, refuses with a provider-shaped 403 before any
// upstream byte, and is never consulted on a hosted app's /up/<id> lane.
func TestPromptAdmitterSeam(t *testing.T) {
	const prompt = `{"model":"claude-x","messages":[{"role":"user","content":"ship it"}]}`
	cases := []struct {
		name       string
		path       string
		block      bool
		inactive   bool
		wantCalled bool
		wantStatus int
		wantHit    bool
	}{
		{name: "default lane, allow forwards", path: "/v1/messages", wantCalled: true, wantStatus: http.StatusOK, wantHit: true},
		{name: "default lane, block refuses", path: "/v1/messages", block: true, wantCalled: true, wantStatus: http.StatusForbidden},
		{name: "openai default lane, block refuses", path: "/v1/chat/completions", block: true, wantCalled: true, wantStatus: http.StatusForbidden},
		{name: "hosted /up lane is never judged", path: "/up/hosted/v1/messages", block: true, wantStatus: http.StatusOK, wantHit: true},
		{name: "no active policy: never consulted (F4)", path: "/v1/messages", block: true, inactive: true, wantStatus: http.StatusOK, wantHit: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hit := false
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hit = true
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"m1","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
			}))
			defer up.Close()
			pa := &fakePromptAdmitter{block: tc.block, inactive: tc.inactive}
			p, err := New(Options{AnthropicUpstream: up.URL, OpenAIUpstream: up.URL, Upstreams: map[string]string{"hosted": up.URL}, Sink: &fakeSink{}, PromptAdmitter: pa})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			ts := httptest.NewServer(p.Handler())
			defer ts.Close()
			resp, err := http.Post(ts.URL+tc.path, "application/json", strings.NewReader(prompt))
			if err != nil {
				t.Fatalf("post: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != tc.wantStatus || hit != tc.wantHit {
				t.Fatalf("status=%d hit=%v body=%s; want %d hit=%v", resp.StatusCode, hit, body, tc.wantStatus, tc.wantHit)
			}
			if (len(pa.calls) > 0) != tc.wantCalled {
				t.Fatalf("admitter called=%v, want %v", len(pa.calls) > 0, tc.wantCalled)
			}
			if tc.wantCalled && string(pa.calls[0].Body) != prompt {
				t.Fatalf("admitter saw body %q", pa.calls[0].Body)
			}
			if tc.block && tc.wantCalled && !strings.Contains(string(body), "not allowed here") {
				t.Fatalf("refusal body lacks the reason: %s", body)
			}
		})
	}
}
