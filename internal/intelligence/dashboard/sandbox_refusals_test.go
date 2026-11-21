package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestSandboxRefusalsRoute pins GET /api/sandbox/refusals (lane N1): the
// filters, newest first, the bounded page and its cursor, the method and
// the cursor's validation, the Local route class and the owning component.
func TestSandboxRefusalsRoute(t *testing.T) {
	s, _ := newTestServer(t)
	st := store.New(s.db())
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-time.Hour)
	for i, r := range []store.SandboxEgressRefusal{
		{RunID: "run-1", ProjectRoot: "/p/one", Host: "a.example", Port: 443, Rule: "allow-list-miss", Key: "terminal.sandbox.egress_allow_hosts"},
		{RunID: "run-1", ProjectRoot: "/p/one", Host: "b.example", Rule: "ssrf-floor"},
		{RunID: "run-2", ProjectRoot: "/p/one", Host: "c.example", Rule: "private-range"},
		{RunID: "run-3", ProjectRoot: "/p/two", Host: "d.example", Rule: "provider-host"},
	} {
		r.At = t0.Add(time.Duration(i) * time.Minute)
		if _, err := st.InsertSandboxEgressRefusal(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	h := s.Handler()
	get := func(query string) (int, sandboxRefusalsPage) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/sandbox/refusals"+query, nil)
		req.Host = "127.0.0.1:8080"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var page sandboxRefusalsPage
		if rec.Code == http.StatusOK {
			if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
				t.Fatalf("%s: %v %s", query, err, rec.Body.String())
			}
		}
		return rec.Code, page
	}
	hosts := func(p sandboxRefusalsPage) string {
		out := ""
		for _, r := range p.Refusals {
			out += r.Host[:1]
		}
		return out
	}
	cases := []struct {
		name, query, want string
	}{
		{"all, newest first", "", "dcba"},
		{"by run", "?run_id=run-1", "ba"},
		{"by project", "?project=/p/one", "cba"},
		{"by run and project", "?run_id=run-3&project=/p/one", ""},
		{"unknown run", "?run_id=nope", ""},
	}
	for _, tc := range cases {
		code, page := get(tc.query)
		if code != http.StatusOK || hosts(page) != tc.want || page.Refusals == nil {
			t.Errorf("%s: %d %q (refusals nil: %v), want %q", tc.name, code, hosts(page), page.Refusals == nil, tc.want)
		}
	}
	code, first := get("?limit=2")
	if code != http.StatusOK || hosts(first) != "dc" || first.NextBefore == 0 {
		t.Fatalf("first page %d %q next %d", code, hosts(first), first.NextBefore)
	}
	_, second := get("?limit=2&before=" + strconv.FormatInt(first.NextBefore, 10))
	if hosts(second) != "ba" {
		t.Fatalf("second page %q", hosts(second))
	}
	_, last := get("?limit=2&before=" + strconv.FormatInt(second.NextBefore, 10))
	if hosts(last) != "" || last.NextBefore != 0 {
		t.Fatalf("last page %q next %d", hosts(last), last.NextBefore)
	}
	// Lane OC, audit finding O3-W2: a run's dropped count rides beside its
	// rows (also for a run whose rows were all dropped), absent for a run
	// that dropped none.
	if err := st.AddSandboxEgressRefusalDrops(ctx, "run-1", 5, 0, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := st.AddSandboxEgressRefusalDrops(ctx, "run-9", 2, 3, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, p := get("?run_id=run-1"); p.Dropped["run-1"] != 5 || len(p.Dropped) != 1 || p.Uncertain != nil {
		t.Fatalf("run-1 dropped %v", p.Dropped)
	}
	if _, p := get("?run_id=run-9"); p.Dropped["run-9"] != 2 || p.Uncertain["run-9"] != 3 || len(p.Refusals) != 0 {
		t.Fatalf("a run with only drops: %+v", p)
	}
	// F-012 (audit finding N4-A4): a run whose link was lost carries its
	// link-lost part and its closed requests beside the dropped count.
	if err := st.AddSandboxEgressRefusalLinkLoss(ctx, "run-9", 4, 6, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, p := get("?run_id=run-9"); p.Dropped["run-9"] != 6 || p.LinkLost["run-9"] != 4 || p.EgressClosed["run-9"] != 6 {
		t.Fatalf("a run whose link was lost: %+v", p)
	}
	if _, p := get("?run_id=run-1"); p.LinkLost != nil || p.EgressClosed != nil {
		t.Fatalf("a run that lost no link: %+v", p)
	}
	if _, p := get("?project=/p/two"); p.Dropped != nil || p.Uncertain != nil {
		t.Fatalf("a page whose runs dropped none: %v", p.Dropped)
	}
	if _, p := get(""); p.Dropped["run-1"] != 5 || p.Dropped["run-9"] != 0 {
		t.Fatalf("the unfiltered page: %v", p.Dropped)
	}
	_, one := get("?run_id=run-1")
	if r := one.Refusals[1]; r.Port != 443 || r.Rule != "allow-list-miss" || r.Key != "terminal.sandbox.egress_allow_hosts" || r.ProjectRoot != "/p/one" || r.At.IsZero() {
		t.Fatalf("row %+v", r)
	}
	if code, _ := get("?before=-1"); code != http.StatusBadRequest {
		t.Fatalf("a bad cursor answered %d", code)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/sandbox/refusals", nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("POST was answered")
	}
	_, capMap, _ := s.registerRoutes(nil)
	if c := capMap["/api/sandbox/refusals"]; c != CapabilityLocal {
		t.Fatalf("route class %v, want Local", c)
	}
	if got := routeComponent("/api/sandbox/refusals"); got != "terminals.sandbox" {
		t.Fatalf("route owner %q, want terminals.sandbox", got)
	}
}
