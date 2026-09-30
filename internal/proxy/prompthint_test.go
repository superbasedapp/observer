package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/requestclass"
)

// claudeCodeHintHeaders is every gateway hint header Claude Code documents
// (https://code.claude.com/docs/en/llm-gateway-protocol#gateway-hint-headers)
// plus the always-sent session id, with representative values.
var claudeCodeHintHeaders = map[string]string{
	"X-Claude-Code-Prompt-Id":           "4b8f1c2e-9d3a-4f6b-8e21-7c5d0a9b3e14",
	"X-Claude-Code-Request-Class":       "main",
	"X-Claude-Code-Agent-Type":          "Explore",
	"X-Claude-Code-Compaction":          "auto",
	"X-Claude-Code-Context-Compacted":   "manual",
	"X-Claude-Code-Prev-Tool-Durations": "Bash=742;Read=9",
	"X-Claude-Code-Session-Id":          "sess-1",
}

// TestPromptHintHeadersForwardedUpstream pins that the proxy forwards every
// Claude Code gateway hint header to the upstream untouched (the proxy is
// a gateway in Anthropic's sense; stripping a hint silently drops it for any
// gateway behind us) AND records the prompt id on the captured turn.
func TestPromptHintHeadersForwardedUpstream(t *testing.T) {
	const responseBody = `{"id":"msg_abc","model":"claude-sonnet-4","stop_reason":"end_turn","usage":{"input_tokens":3,"output_tokens":2}}`
	var mu sync.Mutex
	var seen http.Header
	anth := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = r.Header.Clone()
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	})
	oai := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("openai upstream unexpectedly hit: %s", r.URL.Path)
	})
	p, sink, cleanup := newTestProxy(t, anth, oai)
	defer cleanup()
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/messages",
		strings.NewReader(`{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range claudeCodeHintHeaders {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	mu.Lock()
	got := seen
	mu.Unlock()
	if got == nil {
		t.Fatal("upstream never received the request")
	}
	for k, want := range claudeCodeHintHeaders {
		if v := got.Get(k); v != want {
			t.Errorf("upstream %s = %q, want %q (hint header must pass through untouched)", k, v, want)
		}
	}

	turns := sink.all()
	if len(turns) != 1 {
		t.Fatalf("want 1 turn, got %d", len(turns))
	}
	if want := claudeCodeHintHeaders["X-Claude-Code-Prompt-Id"]; turns[0].PromptID != want {
		t.Errorf("turn PromptID = %q, want %q", turns[0].PromptID, want)
	}
	if want := claudeCodeHintHeaders["X-Claude-Code-Request-Class"]; turns[0].RequestClass != want {
		t.Errorf("turn RequestClass = %q, want %q", turns[0].RequestClass, want)
	}
}

// TestPromptHintHeadersSurviveGatewayCredentialStrip pins that the Gateway
// Mode custody strip (gatewayCredentialHeaders) never names a hint header,
// so a gateway-routed request forwards them like a direct one.
func TestPromptHintHeadersSurviveGatewayCredentialStrip(t *testing.T) {
	for _, h := range gatewayCredentialHeaders {
		if _, hint := claudeCodeHintHeaders[http.CanonicalHeaderKey(h)]; hint {
			t.Errorf("gatewayCredentialHeaders strips hint header %q", h)
		}
	}
	p := &Proxy{}
	src := http.Header{}
	for k, v := range claudeCodeHintHeaders {
		src.Set(k, v)
	}
	dst := http.Header{}
	p.copyRequestHeaders(dst, src)
	for k, want := range claudeCodeHintHeaders {
		if v := dst.Get(k); v != want {
			t.Errorf("copyRequestHeaders dropped %s (got %q, want %q)", k, v, want)
		}
	}
}

// TestPromptIDFromHeader pins the accept/reject table for a stored id.
func TestPromptIDFromHeader(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{"uuid", "4b8f1c2e-9d3a-4f6b-8e21-7c5d0a9b3e14", "4b8f1c2e-9d3a-4f6b-8e21-7c5d0a9b3e14"},
		{"trimmed", "  abc-123  ", "abc-123"},
		{"absent", "", ""},
		{"inner space", "abc 123", ""},
		{"control char", "abc\x01", ""},
		{"non-ascii", "abcé", ""},
		{"at cap", strings.Repeat("a", maxPromptIDLen), strings.Repeat("a", maxPromptIDLen)},
		{"over cap", strings.Repeat("a", maxPromptIDLen+1), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.value != "" {
				h["X-Claude-Code-Prompt-Id"] = []string{tc.value}
			}
			if got := promptIDFromHeader(h); got != tc.want {
				t.Errorf("promptIDFromHeader(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

// TestRequestClassFromHeader pins the closed request-class table: exactly
// the five documented values are stored, anything else is "" (NULL).
func TestRequestClassFromHeader(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{"main", "main", "main"},
		{"subagent", "subagent", "subagent"},
		{"workflow", "workflow", "workflow"},
		{"compaction", "compaction", "compaction"},
		{"auxiliary", "auxiliary", "auxiliary"},
		{"trimmed", "  subagent ", "subagent"},
		{"absent", "", ""},
		{"unknown future class", "background", ""},
		{"different casing not guessed", "Main", ""},
		{"compaction trigger is not a class", "auto", ""},
		{"list not accepted", "main,subagent", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.value != "" {
				h.Set("X-Claude-Code-Request-Class", tc.value)
			}
			if got := requestClassFromHeader(h); got != tc.want {
				t.Errorf("requestClassFromHeader(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
	// Every documented value round-trips to itself: the vocabulary is
	// internal/requestclass's, not a mapping.
	for _, v := range requestclass.Values {
		h := http.Header{}
		h.Set("X-Claude-Code-Request-Class", v)
		if got := requestClassFromHeader(h); got != v {
			t.Errorf("requestClassFromHeader(%q) = %q, want identity", v, got)
		}
	}
	if len(requestclass.Values) != 5 {
		t.Errorf("requestclass.Values has %d rows, want the 5 documented classes", len(requestclass.Values))
	}
}
