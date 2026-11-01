package winrelay

import (
	"strings"
	"testing"
	"time"
)

func TestGateWaitsOnLC6AndLC14(t *testing.T) {
	g := Gate()
	if !g.Waiting() {
		t.Fatal("the relay must stay switched off until LC6 and LC14 pass (DEC-12)")
	}
	if got, want := g.Text(), "built, waiting on live check LC6 and LC14"; got != want {
		t.Fatalf("Gate().Text() = %q, want %q", got, want)
	}
}

func TestRouteURL(t *testing.T) {
	cases := []struct {
		port int
		tool string
		want string
		ok   bool
	}{
		{8829, "claude-code", "http://127.0.0.1:8829/r/claude-code", true},
		{9000, "claude-code", "http://127.0.0.1:9000/r/claude-code", true},
		{8829, "codex", "", false}, // no lane: the direct upstream needs the credential kind
		{8829, "unknown", "", false},
		{0, "claude-code", "", false},
		{70000, "claude-code", "", false},
	}
	for _, c := range cases {
		got, ok := RouteURL(c.port, c.tool)
		if got != c.want || ok != c.ok {
			t.Errorf("RouteURL(%d, %q) = %q, %v; want %q, %v", c.port, c.tool, got, ok, c.want, c.ok)
		}
	}
}

func TestParseRoutePath(t *testing.T) {
	cases := []struct {
		path, tool, rest string
		ok               bool
	}{
		{"/r/claude-code/v1/messages", "claude-code", "/v1/messages", true},
		{"/r/claude-code/v1/messages/count_tokens", "claude-code", "/v1/messages/count_tokens", true},
		{"/r/claude-code", "claude-code", "/", true},
		{"/r/claude-code/", "claude-code", "/", true},
		{"/v1/messages", "", "", false},
		{"/r/", "", "", false},
		{"/r/codex/v1/responses", "", "", false},
		{"/r/../v1", "", "", false},
		{"/rx/claude-code/v1", "", "", false},
	}
	for _, c := range cases {
		tool, rest, ok := ParseRoutePath(c.path)
		if tool != c.tool || rest != c.rest || ok != c.ok {
			t.Errorf("ParseRoutePath(%q) = %q, %q, %v; want %q, %q, %v", c.path, tool, rest, ok, c.tool, c.rest, c.ok)
		}
	}
}

func TestEveryLaneIsHTTPSAndRoundTrips(t *testing.T) {
	for _, l := range Lanes() {
		if !strings.HasPrefix(l.Direct, "https://") {
			t.Errorf("lane %s: direct upstream %q is not https", l.Tool, l.Direct)
		}
		u, ok := RouteURL(DefaultPort, l.Tool)
		if !ok {
			t.Fatalf("lane %s has no route URL", l.Tool)
		}
		path := strings.TrimPrefix(u, "http://127.0.0.1:8829") + "/v1/x"
		if tool, rest, ok := ParseRoutePath(path); !ok || tool != l.Tool || rest != "/v1/x" {
			t.Errorf("lane %s: route path %q parsed as %q %q %v", l.Tool, path, tool, rest, ok)
		}
	}
}

func TestValidatePorts(t *testing.T) {
	cases := []struct {
		listen, proxy int
		ok            bool
	}{
		{DefaultPort, DefaultProxyPort, true},
		{9001, 9000, true},
		{9000, 9000, false},
		{DefaultProxyPort, 9000, false}, // the proxy's default port is never the relay's
		{0, DefaultProxyPort, false},
		{DefaultPort, 0, false},
		{DefaultPort, 65536, false},
	}
	for _, c := range cases {
		err := ValidatePorts(c.listen, c.proxy)
		if (err == nil) != c.ok {
			t.Errorf("ValidatePorts(%d, %d) = %v, want ok=%v", c.listen, c.proxy, err, c.ok)
		}
	}
	if DefaultPort == DefaultProxyPort {
		t.Fatal("the relay's default port must not be the proxy's")
	}
}

// TestDecide has one row per decision-table rule, plus the precedence rows.
func TestDecide(t *testing.T) {
	cases := []struct {
		name string
		f    Facts
		want Decision
	}{
		{"non-loopback peer is refused first", Facts{LoopbackPeer: false, LaneKnown: true, ProxyReachable: true}, DecisionRefusePeer},
		{"unknown lane is refused", Facts{LoopbackPeer: true, LaneKnown: false, ProxyReachable: true}, DecisionRefuseLane},
		{"proxy reachable forwards to the proxy", Facts{LoopbackPeer: true, LaneKnown: true, ProxyReachable: true}, DecisionForwardProxy},
		{"proxy unreachable fails open", Facts{LoopbackPeer: true, LaneKnown: true, ProxyReachable: false}, DecisionFailOpen},
		{"non-loopback peer never fails open", Facts{}, DecisionRefusePeer},
	}
	for _, c := range cases {
		if got := Decide(c.f); got != c.want {
			t.Errorf("%s: Decide = %q, want %q", c.name, got, c.want)
		}
	}
	if NeedsProxyDial(Facts{LoopbackPeer: true}) || NeedsProxyDial(Facts{LaneKnown: true}) || !NeedsProxyDial(Facts{LoopbackPeer: true, LaneKnown: true}) {
		t.Error("the proxy is dialled only for a loopback request on a known lane")
	}
}

func TestSanitize(t *testing.T) {
	for in, want := range map[string]string{
		"/v1/messages":                    "/v1/messages",
		"":                                "/",
		"/v1/models/claude:count":         "/v1/models/claude:count",
		"/v1/x y":                         "other",
		"/v1/%2e%2e":                      "other",
		"/v1/" + strings.Repeat("a", 300): "/v1/" + strings.Repeat("a", 124),
	} {
		if got := SanitizePath(in); got != want {
			t.Errorf("SanitizePath(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"POST": "POST", "post": "OTHER", "": "OTHER", "PO\nST": "OTHER"} {
		if got := SanitizeMethod(in); got != want {
			t.Errorf("SanitizeMethod(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestJournalRoundTripAndSummary(t *testing.T) {
	t0 := time.Date(2026, 10, 28, 10, 0, 0, 0, time.FixedZone("x", 3600))
	var data []byte
	for i, e := range []Entry{
		{At: t0, Tool: "claude-code", Upstream: "api.anthropic.com", Method: "POST", Path: "/v1/messages", Reason: ReasonProxyUnreachable},
		{At: t0.Add(time.Hour), Tool: "claude-code", Upstream: "api.anthropic.com", Method: "POST", Path: "/v1/messages", Reason: ReasonProxyUnreachable},
		{At: t0.Add(-48 * time.Hour), Tool: "claude-code", Upstream: "api.anthropic.com", Method: "POST", Path: "/v1/messages", Reason: ReasonProxyUnreachable},
	} {
		line, err := Encode(e)
		if err != nil {
			t.Fatalf("Encode %d: %v", i, err)
		}
		if !strings.Contains(string(line), `"at":"2026-`) || !strings.HasSuffix(string(line), "\n") {
			t.Fatalf("line %d = %q", i, line)
		}
		data = append(data, line...)
	}
	data = append(data, []byte("not json\n{\"tool\":\"claude-code\"}\n{\"at\":\"2026-10-28T12:00:00Z\",\"tool\":\"claude")...)
	entries, skipped := ParseJournal(data)
	if len(entries) != 3 || skipped != 3 {
		t.Fatalf("ParseJournal = %d entries, %d skipped; want 3, 3", len(entries), skipped)
	}
	s := Summarize(entries, t0.Add(-time.Minute), skipped)
	if s.Total() != 2 || len(s.Tools) != 1 || s.Tools[0].Count != 2 || s.Skipped != 3 {
		t.Fatalf("Summarize = %+v", s)
	}
	if !s.Tools[0].First.Equal(t0) || !s.Tools[0].Last.Equal(t0.Add(time.Hour)) {
		t.Fatalf("first/last = %v / %v", s.Tools[0].First, s.Tools[0].Last)
	}
	if Summarize(entries, t0.Add(2*time.Hour), 0).Total() != 0 {
		t.Fatal("entries before the window must not count")
	}
}

// TestEntryCarriesNoCredentialField pins the journal's field set: a new
// field is a privacy decision, made here and in docs/security.md together.
func TestEntryCarriesNoCredentialField(t *testing.T) {
	line, err := Encode(Entry{At: time.Unix(0, 0), Tool: "claude-code"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"at":"1970-01-01T00:00:00Z","tool":"claude-code","upstream":"","method":"","path":"","reason":""}` + "\n"
	if string(line) != want {
		t.Fatalf("journal line = %s, want %s", line, want)
	}
}
