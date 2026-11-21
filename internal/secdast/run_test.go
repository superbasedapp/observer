package secdast

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// fakeFetch answers from a path table and records the requests.
type fakeFetch struct {
	answers map[string]Response
	got     []Request
}

func (f *fakeFetch) fetch(_ context.Context, req Request) Response {
	f.got = append(f.got, req)
	if r, ok := f.answers[req.Path]; ok {
		return r
	}
	return Response{Status: 404, Header: Header{"content-type": {"text/plain"}}, Body: []byte("not found")}
}

func TestRunProbesInOrderAndFindsMaps(t *testing.T) {
	t.Parallel()
	tg, _ := ParseTarget("http://localhost:3000/")
	body := `<html><head>
<script src="/static/app.js"></script>
<script src='vendor.js' defer></script>
<script src=https://cdn.example.com/x.js></script>
<script src="/static/app.js"></script>
<script src="/a.js"></script><script src="/b.js"></script>
</head></html>`
	f := &fakeFetch{answers: map[string]Response{
		"/":                  {Status: 200, Header: Header{"content-type": {"text/html"}}, Body: []byte(body)},
		"/static/app.js":     {Status: 200, Header: Header{"content-type": {"text/javascript"}}, Body: []byte("x()\n//# sourceMappingURL=app.js.map\n")},
		"/vendor.js":         {Status: 200, Header: Header{"sourcemap": {"/maps/vendor.map"}}, Body: []byte("y()")},
		"/a.js":              {Status: 200, Body: []byte("//# sourceMappingURL=data:application/json;base64,e30=")},
		"/static/app.js.map": {Status: 200, Body: []byte(`{"version":3,"sources":["a"],"mappings":"A"}`)},
	}}
	rep := Run(context.Background(), tg, "Tok-42!", f.fetch)
	var paths []string
	for _, r := range f.got {
		paths = append(paths, r.ID+" "+r.Path)
	}
	want := []string{
		"page /", "git-head /.git/HEAD", "env /.env", "not-found /observer-dast-tok42",
		"script-1 /static/app.js", "map-1 /static/app.js.map",
		"script-2 /vendor.js", "map-2 /maps/vendor.map",
		"script-3 /a.js",
	}
	if strings.Join(paths, "|") != strings.Join(want, "|") {
		t.Fatalf("requests\n got %v\nwant %v", paths, want)
	}
	if f.got[0].Origin != CanaryOrigin {
		t.Errorf("the page probe carries Origin %q", f.got[0].Origin)
	}
	for _, r := range f.got[1:] {
		if r.Origin != "" {
			t.Errorf("%s carries an Origin header", r.ID)
		}
	}
	if rep.Outcome != OutcomeComplete || rep.Requests != len(want) || rep.Checks != len(Checks()) {
		t.Errorf("report %+v", rep)
	}
	found := false
	for _, h := range rep.Hits {
		if h.Check == "dast.exposed.sourcemap" && h.Path == "/static/app.js.map" {
			found = true
		}
	}
	if !found {
		t.Errorf("source map not reported: %+v", rep.Hits)
	}
}

func TestRunUnreachableReportsNothing(t *testing.T) {
	t.Parallel()
	tg, _ := ParseTarget("http://localhost:3000/")
	calls := 0
	rep := Run(context.Background(), tg, "x", func(context.Context, Request) Response {
		calls++
		return Response{Err: "connection refused"}
	})
	if rep.Outcome != OutcomeUnreachable || len(rep.Hits) != 0 || calls != 1 || rep.Checks != 0 {
		t.Fatalf("unreachable run: %+v after %d calls", rep, calls)
	}
}

func TestRunPartialAndCapped(t *testing.T) {
	t.Parallel()
	tg, _ := ParseTarget("http://localhost:3000/")
	rep := Run(context.Background(), tg, "x", func(_ context.Context, req Request) Response {
		if req.Path == "/.env" {
			return Response{Err: "timeout"}
		}
		return Response{Status: 200, Header: Header{"content-type": {"text/html"}}, Body: []byte(htmlPage)}
	})
	if rep.Outcome != OutcomePartial || len(rep.Errors) != 1 || rep.Errors[0].Probe != ProbeEnv {
		t.Fatalf("partial run: %+v", rep)
	}
	ctx, cancel := context.WithCancel(context.Background())
	n := 0
	rep = Run(ctx, tg, "x", func(context.Context, Request) Response {
		n++
		if n == 2 {
			cancel()
		}
		return Response{Status: 200}
	})
	if n != 2 || rep.Outcome != OutcomePartial {
		t.Fatalf("a cancelled run went on: %d requests, %+v", n, rep)
	}
	if MaxRequests < 4+2*MaxScripts {
		t.Fatalf("MaxRequests %d cannot hold the fixed probes and %d scripts", MaxRequests, MaxScripts)
	}
}

func TestFindingsShape(t *testing.T) {
	t.Parallel()
	tg, _ := ParseTarget("http://localhost:3000/")
	hits := []Hit{
		{Check: "dast.exposed.env", Path: "/.env", Evidence: "GET /.env (200, 10 bytes): 1 NAME=value lines (values not read)"},
		{Check: "dast.unknown", Path: "/"},
	}
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	fs := Findings(tg, hits, now, func(s string) string { return strings.ReplaceAll(s, "10 bytes", "[n] bytes") })
	if len(fs) != 1 {
		t.Fatalf("%d findings, want 1 (an unknown check id is dropped)", len(fs))
	}
	f := fs[0]
	if f.Rule.ID != "dast.exposed.env" || f.Engine.Driver != Driver || f.Category != policy.FindingCodeVuln ||
		f.Scope != policy.FindingScopeManual || f.Status != policy.FindingStatusOpen || f.Severity != policy.FindingSeverityHigh ||
		f.Message == "" || f.FixHint == "" || f.LocalKey == "" || f.EvidenceHash == "" || !f.FirstSeen.Equal(now) ||
		!strings.Contains(f.EvidenceRedacted, "[n] bytes") || len(f.References.CWE) == 0 {
		t.Fatalf("finding %+v", f)
	}
	other, _ := ParseTarget("http://localhost:4000/")
	if Findings(other, hits, now, nil)[0].LocalKey == f.LocalKey {
		t.Error("the same check on two servers shares a local key")
	}
}

func TestLaunchCandidates(t *testing.T) {
	t.Parallel()
	data := []byte(`{"version":"0.0.1","configurations":[
	 {"name":"web","runtimeExecutable":"npm","port":5173},
	 {"name":"api","port":"8080"},
	 {"name":"tls","url":"https://localhost:8443"},
	 {"name":"remote","url":"https://staging.example.com"},
	 {"name":"dup","port":5173},
	 {"name":"bad","port":70000},
	 {"name":"none"}]}`)
	got := LaunchCandidates(data)
	var urls []string
	for _, c := range got {
		urls = append(urls, c.Name+"="+c.URL)
	}
	want := "web=http://localhost:5173/|api=http://localhost:8080/|tls=https://localhost:8443/"
	if strings.Join(urls, "|") != want {
		t.Fatalf("candidates %v, want %s", urls, want)
	}
	if LaunchCandidates([]byte("not json")) != nil || LaunchCandidates(nil) != nil {
		t.Error("malformed input gave candidates")
	}
}
