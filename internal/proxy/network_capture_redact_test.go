package proxy

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRedactCredentialQueryText(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"https://g.example/v1beta/models/x:generateContent?key=AIzaSECRET", "https://g.example/v1beta/models/x:generateContent?key=REDACTED"},
		{"https://g.example/p?alt=sse&key=AIzaSECRET&x=1", "https://g.example/p?alt=sse&key=REDACTED&x=1"},
		{`Post "http://127.0.0.1:1/p?key=AIzaSECRET": dial tcp: refused`, `Post "http://127.0.0.1:1/p?key=REDACTED": dial tcp: refused`},
		{"https://g.example/p?monkey=banana", "https://g.example/p?monkey=banana"},
	}
	for _, tc := range cases {
		if got := redactCredentialQueryText(tc.in); got != tc.want {
			t.Errorf("redact(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestProxy_ProcessNetworkCaptureRedactsGeminiKey is the SR27-D3 regression
// (security review 2026-09-27). A direct-provider Gemini request carries the
// developer's API key as ?key=; with network capture on, the upstream URL and a
// transport error's text (a *url.Error embeds the whole URL) were persisted
// verbatim into the process-network event (target, details.url, details.error)
// - rows that ship to the org on a full-content node.
func TestProxy_ProcessNetworkCaptureRedactsGeminiKey(t *testing.T) {
	const secret = "AIzaSyDEADBEEFsecretKEY0123456789abcdefg"
	// An upstream that refuses the connection: grab a free port, close it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadURL := "http://" + ln.Addr().String()
	_ = ln.Close()

	netSink := &fakeNetworkSink{}
	p, err := New(Options{
		AnthropicUpstream: "https://api.anthropic.com",
		OpenAIUpstream:    "https://api.openai.com",
		GeminiUpstream:    deadURL,
		Sink:              &fakeSink{},
		NetworkSink:       netSink,
		NetworkCapture:    NetworkCaptureOptions{Enabled: true, CaptureBodies: "proxied"},
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+geminiPath+"?key="+secret, "application/json", strings.NewReader(geminiBody))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	events := netSink.waitForCount(1)
	if len(events) == 0 {
		t.Fatal("no network event captured for the failed Gemini call")
	}
	for _, ev := range events {
		raw, _ := json.Marshal(ev)
		if strings.Contains(string(raw), secret) {
			t.Fatalf("captured network event carries the Gemini API key: %s", raw)
		}
		if !strings.Contains(ev.Target, "key=REDACTED") {
			t.Errorf("target = %q, want the key param kept but redacted", ev.Target)
		}
	}
}
