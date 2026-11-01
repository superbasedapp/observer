package planlimitsnet

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/planlimits"
)

func TestCheckURLTable(t *testing.T) {
	src, _ := planlimits.SourceByID(planlimits.SourceOpenRouter)
	cases := map[string]bool{
		"https://openrouter.ai/api/v1/key":       true,
		"https://OpenRouter.ai/api/v1/key":       true,
		"https://openrouter.ai:443/api/v1/key":   true,
		"http://openrouter.ai/api/v1/key":        false,
		"https://openrouter.ai:8443/api":         false,
		"https://user:pw@openrouter.ai/api":      false,
		"https://openrouter.ai.evil.test/api":    false,
		"https://evil.test/?h=openrouter.ai":     false,
		"https://openrouter.ai/api#frag":         false,
		"https://openrouter.ai%2F@evil.test/api": false,
	}
	for u, ok := range cases {
		if err := CheckURL(src, u); (err == nil) != ok {
			t.Errorf("%s: err=%v want ok=%v", u, err, ok)
		}
	}
}

// TestCheckURLAgainstBaseTable pins the self-hosted gateway policy (ledger
// SUBS-5): the request must use the base's scheme, host and port exactly,
// and the base itself must pass planlimits.CheckBaseURL.
func TestCheckURLAgainstBaseTable(t *testing.T) {
	gw := planlimits.SourceDef{ID: "test.gateway", UserBaseURL: true}
	cases := []struct {
		name, base, raw string
		ok              bool
	}{
		{"https same host", "https://gw.example.com", "https://gw.example.com/key/info", true},
		{"https same host with base path", "https://gw.example.com/litellm", "https://gw.example.com/litellm/key/info", true},
		{"https custom port", "https://gw.example.com:8443", "https://gw.example.com:8443/key/info", true},
		{"https explicit default port equals none", "https://gw.example.com", "https://gw.example.com:443/x", true},
		{"host case folds", "https://GW.example.com", "https://gw.EXAMPLE.com/x", true},
		{"http loopback ipv4", "http://127.0.0.1:4000", "http://127.0.0.1:4000/key/info", true},
		{"http loopback ipv6", "http://[::1]:4000", "http://[::1]:4000/key/info", true},
		{"http localhost", "http://localhost:4000", "http://localhost:4000/key/info", true},
		{"request query allowed", "https://gw.example.com", "https://gw.example.com/x?a=1", true},
		{"other host", "https://gw.example.com", "https://evil.test/key/info", false},
		{"suffix host", "https://gw.example.com", "https://gw.example.com.evil.test/x", false},
		{"other port", "https://gw.example.com:8443", "https://gw.example.com:9443/x", false},
		{"port added", "https://gw.example.com", "https://gw.example.com:8443/x", false},
		{"scheme downgrade", "https://gw.example.com", "http://gw.example.com/x", false},
		{"scheme upgrade", "http://localhost:4000", "https://localhost:4000/x", false},
		{"request user info", "https://gw.example.com", "https://u:p@gw.example.com/x", false},
		{"request fragment", "https://gw.example.com", "https://gw.example.com/x#f", false},
		{"encoded at", "https://gw.example.com", "https://gw.example.com%2F@evil.test/x", false},
		{"http to a remote host", "http://gw.example.com", "http://gw.example.com/x", false},
		{"http to a lan address", "http://192.168.1.5:4000", "http://192.168.1.5:4000/x", false},
		{"http to another loopback", "http://127.0.0.2:4000", "http://127.0.0.2:4000/x", false},
		{"base with user info", "https://u:p@gw.example.com", "https://gw.example.com/x", false},
		{"base with query", "https://gw.example.com?a=1", "https://gw.example.com/x", false},
		{"base with fragment", "https://gw.example.com#f", "https://gw.example.com/x", false},
		{"empty base", "", "https://gw.example.com/x", false},
		{"base other scheme", "ftp://gw.example.com", "ftp://gw.example.com/x", false},
	}
	for _, c := range cases {
		if err := CheckURLAgainstBase(gw, c.base, c.raw); (err == nil) != c.ok {
			t.Errorf("%s: base %q url %q: err=%v want ok=%v", c.name, c.base, c.raw, err, c.ok)
		}
	}
	fixed, _ := planlimits.SourceByID(planlimits.SourceOpenRouter)
	if err := CheckURLAgainstBase(fixed, "https://openrouter.ai", "https://openrouter.ai/api"); err == nil {
		t.Error("a fixed-host source must never take a base URL")
	}
	if err := CheckURL(gw, "https://gw.example.com/x"); err == nil {
		t.Error("a gateway source must never pass the fixed-host check")
	}
}

// TestGatewayAnchorIsCheckedAndNeverSent: the base travels in a reserved
// header that the egress reads and strips; without it, or on a fixed-host
// source, nothing is sent.
func TestGatewayAnchorIsCheckedAndNeverSent(t *testing.T) {
	var got []*http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Clone(r.Context()))
		_, _ = io.WriteString(w, `{}`)
	}))
	defer srv.Close()
	base, _ := url.Parse(srv.URL)
	c := New(Options{HTTP: &http.Client{Transport: &rewrite{base: base}}, Version: "test"})
	gw := planlimits.SourceDef{ID: "test.gateway", UserBaseURL: true}
	const anchor = "https://gw.example.com:8443"
	accept := map[string]string{"Accept": "application/json"}
	res := c.Do(context.Background(), gw, []planlimits.Request{
		{Key: "ok", Kind: planlimits.ReqHTTP, URL: "https://gw.example.com:8443/key/info", Header: accept, Base: anchor, SecretHeaders: map[string]string{"Authorization": "Bearer K"}},
		{Key: "noanchor", Kind: planlimits.ReqHTTP, URL: "https://gw.example.com:8443/key/info", SecretHeaders: map[string]string{"Authorization": "Bearer K"}},
		{Key: "otherhost", Kind: planlimits.ReqHTTP, URL: "https://evil.test:8443/key/info", Header: accept, Base: anchor, SecretHeaders: map[string]string{"Authorization": "Bearer K"}},
	})
	if res["ok"].Err != nil || res["ok"].Status != 200 {
		t.Errorf("anchored request %+v", res["ok"])
	}
	for _, k := range []string{"noanchor", "otherhost"} {
		if !errors.Is(res[k].Err, ErrHostNotAllowed) {
			t.Errorf("%s must be refused: %+v", k, res[k])
		}
	}
	fixed, _ := planlimits.SourceByID(planlimits.SourceOpenRouter)
	res = c.Do(context.Background(), fixed, []planlimits.Request{{
		Key: "smuggle", Kind: planlimits.ReqHTTP, URL: "https://openrouter.ai/api/v1/key",
		Base: "https://openrouter.ai",
	}})
	if !errors.Is(res["smuggle"].Err, ErrHostNotAllowed) {
		t.Errorf("a fixed-host source must refuse an anchor: %+v", res["smuggle"])
	}
	if len(got) != 1 {
		t.Fatalf("sent %d requests, want 1", len(got))
	}
	if got[0].Header.Get("Accept") != "application/json" {
		t.Errorf("plain headers must be kept: %v", got[0].Header)
	}
}

// rewrite sends every request to the test server, keeping the original host
// in the URL the client checked.
type rewrite struct {
	base *url.URL
	seen []*http.Request
}

func (r *rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	r.seen = append(r.seen, req.Clone(req.Context()))
	out := req.Clone(req.Context())
	out.URL.Scheme, out.URL.Host = r.base.Scheme, r.base.Host
	return http.DefaultTransport.RoundTrip(out)
}

func TestDoHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/key":
			if r.Header.Get("Authorization") != "Bearer K" {
				w.WriteHeader(401)
				return
			}
			_, _ = io.WriteString(w, `{"data":{}}`)
		case "/api/v1/credits":
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(429)
		case "/redirect":
			http.Redirect(w, r, "https://evil.test/", http.StatusFound)
		}
	}))
	defer srv.Close()
	base, _ := url.Parse(srv.URL)
	rt := &rewrite{base: base}
	c := New(Options{HTTP: &http.Client{Transport: rt}, Version: "test"})
	src, _ := planlimits.SourceByID(planlimits.SourceOpenRouter)
	res := c.Do(context.Background(), src, []planlimits.Request{
		{Key: "key", Kind: planlimits.ReqHTTP, URL: "https://openrouter.ai/api/v1/key", SecretHeaders: map[string]string{"Authorization": "Bearer K"}},
		{Key: "credits", Kind: planlimits.ReqHTTP, URL: "https://openrouter.ai/api/v1/credits"},
		{Key: "redir", Kind: planlimits.ReqHTTP, URL: "https://openrouter.ai/redirect"},
		{Key: "evil", Kind: planlimits.ReqHTTP, URL: "https://evil.test/x", SecretHeaders: map[string]string{"Authorization": "Bearer K"}},
	})
	if res["key"].Status != 200 || string(res["key"].Body) != `{"data":{}}` {
		t.Errorf("key %+v", res["key"])
	}
	if res["credits"].Status != 429 || res["credits"].RetryAfter != 7*time.Second {
		t.Errorf("credits %+v", res["credits"])
	}
	if res["redir"].Err == nil {
		t.Error("a redirect must never be followed")
	}
	if !errors.Is(res["evil"].Err, ErrHostNotAllowed) {
		t.Errorf("evil host %+v", res["evil"])
	}
	for _, r := range rt.seen {
		if r.URL.Host == "evil.test" {
			t.Fatal("a refused host must never be contacted")
		}
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "superbased-observer-plans/") {
			t.Errorf("user agent %q", r.Header.Get("User-Agent"))
		}
	}
	if len(rt.seen) != 3 {
		t.Errorf("sent %d requests, want 3", len(rt.seen))
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	if ParseRetryAfter("30", now) != 30*time.Second || ParseRetryAfter("", now) != 0 || ParseRetryAfter("soon", now) != 0 {
		t.Error("seconds form")
	}
	if got := ParseRetryAfter(now.Add(time.Minute).Format(http.TimeFormat), now); got != time.Minute {
		t.Errorf("date form %s", got)
	}
}

func TestExecPolicy(t *testing.T) {
	src, _ := planlimits.SourceByID(planlimits.SourceKiroCLI)
	c := New(Options{Resolve: func(string) (string, error) { return "", errors.New("never resolved") }})
	res := c.Do(context.Background(), src, []planlimits.Request{{Key: "out", Kind: planlimits.ReqExec, Argv: []string{"sh", "-c", "id"}}})
	if !errors.Is(res["out"].Err, planlimits.ErrShape) {
		t.Errorf("a command other than the source's must be refused: %+v", res["out"])
	}
	c = New(Options{Getenv: func(k string) string {
		if k == "PATH" {
			return t.TempDir()
		}
		return ""
	}})
	res = c.Do(context.Background(), src, []planlimits.Request{{Key: "out", Kind: planlimits.ReqExec, Argv: []string{"kiro-cli", "chat"}}})
	if !errors.Is(res["out"].Err, planlimits.ErrUnavailable) {
		t.Errorf("a missing CLI is unavailable: %+v", res["out"])
	}
}

func TestExecSkipsShimDirAndRunsFixedArgv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fixture")
	}
	shim, real := t.TempDir(), t.TempDir()
	write := func(dir, body string) {
		if err := os.WriteFile(filepath.Join(dir, "amp"), []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write(shim, "echo SHIM")
	write(real, `echo "args:$*"; echo "secret:${OPENAI_API_KEY:-none}"`)
	env := map[string]string{"PATH": shim + string(os.PathListSeparator) + real, "OPENAI_API_KEY": "leak"}
	c := New(Options{ExcludeDirs: []string{shim}, Getenv: func(k string) string { return env[k] }})
	src, _ := planlimits.SourceByID(planlimits.SourceAmpCLI)
	reqs, _ := planlimits.Drivers[planlimits.SourceAmpCLI].Plan(planlimits.PlanInput{})
	res := c.Do(context.Background(), src, reqs)
	out := string(res["out"].Body)
	if strings.Contains(out, "SHIM") || !strings.Contains(out, "args:usage") {
		t.Errorf("resolved the shim or wrong argv: %q", out)
	}
	if !strings.Contains(out, "secret:none") {
		t.Errorf("only allow-listed variables reach a vendor command: %q", out)
	}
}

// TestRedirectIsClassifiedBySourceKind: a redirect is never followed; for a
// pasted browser session it means the session expired (sign in again), for
// any other source that the endpoint moved.
func TestRedirectIsClassifiedBySourceKind(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/login", http.StatusFound)
	}))
	defer srv.Close()
	base, _ := url.Parse(srv.URL)
	c := New(Options{HTTP: &http.Client{Transport: &rewrite{base: base}}, Version: "test"})
	cases := []struct {
		kind planlimits.SourceKind
		want error
	}{
		{planlimits.KindBrowser, planlimits.ErrAuth},
		{planlimits.KindOfficialAPI, planlimits.ErrShape},
		{planlimits.KindUndocumented, planlimits.ErrShape},
	}
	for _, tc := range cases {
		src := planlimits.SourceDef{ID: "t", Kind: tc.kind, Hosts: []string{"vendor.example"}}
		res := c.Do(context.Background(), src, []planlimits.Request{{Key: "k", Kind: planlimits.ReqHTTP, URL: "https://vendor.example/usage"}})
		if !errors.Is(res["k"].Err, tc.want) {
			t.Errorf("%s: redirect gave %v, want %v", tc.kind, res["k"].Err, tc.want)
		}
	}
}
