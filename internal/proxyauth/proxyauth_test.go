package proxyauth

import (
	"strings"
	"testing"
)

const (
	tokA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tokB = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

func TestValidToken(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		in   string
		want bool
	}{
		{tokA, true},
		{"", false},
		{tokA[:63], false},
		{tokA + "0", false},
		{strings.ToUpper(tokA), false},
		{strings.Repeat("g", 64), false},
	} {
		if got := ValidToken(c.in); got != c.want {
			t.Errorf("ValidToken(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSplitPath(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		path, tok, rest string
		found           bool
	}{
		{"/t/" + tokA + "/v1/messages", tokA, "/v1/messages", true},
		{"/t/" + tokA, tokA, "/", true},
		{"/t/" + tokA + "/", tokA, "/", true},
		{"/t/" + tokA + "/up/grok/v1/chat", tokA, "/up/grok/v1/chat", true},
		{"/v1/messages", "", "/v1/messages", false},
		{"/tt/x", "", "/tt/x", false},
		{"/t", "", "/t", false},
	} {
		tok, rest, found := SplitPath(c.path)
		if tok != c.tok || rest != c.rest || found != c.found {
			t.Errorf("SplitPath(%q) = %q, %q, %v; want %q, %q, %v", c.path, tok, rest, found, c.tok, c.rest, c.found)
		}
	}
}

// TestDecideTable has one case per decision table row (and the corners
// between them).
func TestDecideTable(t *testing.T) {
	t.Parallel()
	ok := "/t/" + tokA + "/v1/messages"
	wrong := "/t/" + tokB + "/v1/messages"
	for _, c := range []struct {
		name string
		req  Request
		want Verdict
	}{
		{"no token configured, plain path", Request{Path: "/v1/messages"}, Pass},
		{"no token configured, required ignored", Request{Required: true, Path: "/v1/messages"}, Pass},
		{"no token configured, a token-shaped prefix is refused, never forwarded", Request{Path: ok}, Refuse},
		{"no token configured, a /t/ path that is not a token passes", Request{Path: "/t/abc/v1"}, Pass},
		{"token matches", Request{Configured: tokA, Path: ok}, Accept},
		{"token matches, required", Request{Configured: tokA, Required: true, Path: ok}, Accept},
		{"wrong token, not required", Request{Configured: tokA, Path: wrong}, Refuse},
		{"wrong token, required", Request{Configured: tokA, Required: true, Path: wrong}, Refuse},
		{"empty token segment", Request{Configured: tokA, Path: "/t//v1"}, Refuse},
		{"no token, required", Request{Configured: tokA, Required: true, Path: "/v1/messages"}, Refuse},
		{"no token, not required", Request{Configured: tokA, Path: "/v1/messages"}, Pass},
	} {
		got := Decide(c.req)
		if got.Verdict != c.want {
			t.Errorf("%s: verdict %v, want %v", c.name, got.Verdict, c.want)
		}
		if got.Verdict == Refuse && (got.Status != StatusUnauthorized || got.Reason == "") {
			t.Errorf("%s: refusal %d %q, want 401 with a reason", c.name, got.Status, got.Reason)
		}
		if strings.Contains(got.Reason, tokA) || strings.Contains(got.Reason, tokB) {
			t.Errorf("%s: the reason carries a token", c.name)
		}
	}
}

func TestEnforceTable(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name     string
		in       EnforceFacts
		enforce  bool
		blocking int
	}{
		{"not requested", EnforceFacts{TokenReady: true}, false, 0},
		{"no token", EnforceFacts{Requested: true}, false, 0},
		{"plain route blocks", EnforceFacts{Requested: true, TokenReady: true, PlainRoutes: []string{"kimi-code"}}, false, 1},
		{"every route carries it", EnforceFacts{Requested: true, TokenReady: true}, true, 0},
	} {
		got := Enforce(c.in)
		if got.Enforce != c.enforce || len(got.Blocking) != c.blocking || got.Reason == "" {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
}

func TestWithTokenAndStrip(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ base, want string }{
		{"http://127.0.0.1:8820", "http://127.0.0.1:8820/t/" + tokA},
		{"http://127.0.0.1:8820/", "http://127.0.0.1:8820/t/" + tokA},
		{"http://127.0.0.1:8820/v1", "http://127.0.0.1:8820/t/" + tokA + "/v1"},
		{"http://127.0.0.1:8820/up/grok/v1", "http://127.0.0.1:8820/t/" + tokA + "/up/grok/v1"},
		{"http://127.0.0.1:8820/t/" + tokB + "/v1", "http://127.0.0.1:8820/t/" + tokA + "/v1"},
	} {
		got := WithToken(c.base, tokA)
		if got != c.want {
			t.Errorf("WithToken(%q) = %q, want %q", c.base, got, c.want)
		}
		if !HasToken(got) {
			t.Errorf("HasToken(%q) = false", got)
		}
		plain, had := StripToken(got)
		if !had || HasToken(plain) || strings.Contains(plain, tokA) {
			t.Errorf("StripToken(%q) = %q, %v", got, plain, had)
		}
	}
	if got := WithToken("http://127.0.0.1:8820/t/"+tokB+"/v1", ""); got != "http://127.0.0.1:8820/v1" {
		t.Errorf("WithToken with no token = %q, want the plain form", got)
	}
	if got := WithToken("not a url", tokA); got != "not a url" {
		t.Errorf("WithToken on a non-URL = %q", got)
	}
	if HasToken("http://127.0.0.1:8820/v1") {
		t.Error("HasToken on a plain URL")
	}
}

func TestRedactAndSameRoute(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ in, want string }{
		{"http://127.0.0.1:8820/t/" + tokA + "/v1", "http://127.0.0.1:8820/t/<redacted>/v1"},
		{"http://127.0.0.1:8820/t/" + tokA, "http://127.0.0.1:8820/t/<redacted>"},
		{"http://127.0.0.1:8820/v1", "http://127.0.0.1:8820/v1"},
		{"garbage", "garbage"},
	} {
		if got := Redact(c.in); got != c.want {
			t.Errorf("Redact(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if !SameRoute("http://127.0.0.1:8820/t/"+tokA+"/v1", "http://127.0.0.1:8820/v1") {
		t.Error("SameRoute: token and plain form of one route")
	}
	if SameRoute("http://127.0.0.1:8821/v1", "http://127.0.0.1:8820/v1") {
		t.Error("SameRoute: two ports")
	}
}

func TestTokenOf(t *testing.T) {
	t.Parallel()
	if got := TokenOf("http://127.0.0.1:8820/t/" + tokA + "/v1"); got != tokA {
		t.Errorf("TokenOf = %q", got)
	}
	if got := TokenOf("http://127.0.0.1:8820/v1"); got != "" {
		t.Errorf("TokenOf plain = %q", got)
	}
}
