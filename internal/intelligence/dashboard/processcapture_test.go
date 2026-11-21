package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/proccapture"
	"github.com/marmutapp/superbased-observer/internal/procmodel"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// procGet serves one GET through the loopback handler and decodes a 200.
func procGet(t *testing.T, s *Server, path string, hdr map[string]string, out any) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	s.Handler().ServeHTTP(rr, req)
	if rr.Code == http.StatusOK && out != nil {
		if err := json.Unmarshal(rr.Body.Bytes(), out); err != nil {
			t.Fatalf("decode %s: %v - %s", path, err, rr.Body.String())
		}
	}
	return rr
}

// seedSessionRuns stores n exited runs for session sA, one per second, all
// children of the first.
func seedSessionRuns(t *testing.T, s *Server, n int, base time.Time) {
	t.Helper()
	var runs []procmodel.ProcessRun
	for i := range n {
		parent := ""
		if i > 0 {
			parent = "r-000"
		}
		runs = append(runs, dashProcRun(fmt.Sprintf("r-%03d", i), parent, "sA", 100+i, "git", "git status", base.Add(time.Duration(i)*time.Second)))
	}
	if _, err := store.New(s.db()).PersistRuns(context.Background(), runs); err != nil {
		t.Fatalf("PersistRuns: %v", err)
	}
}

func countTree(nodes []ProcessNode) int {
	n := 0
	for _, x := range nodes {
		n += 1 + countTree(x.Children)
	}
	return n
}

// TestProcessSummaryLegacyAndBudget pins the summary (plan §9.3): a session
// with no stats row is legacy with its plain row count; a session with a
// stats row reports the counters, the budget, its service roots and its
// rollups; an unknown session is a 404.
func TestProcessSummaryLegacyAndBudget(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	st := store.New(s.db())
	base := time.Now().UTC().Add(-20 * time.Minute)
	seedSessionRuns(t, s, 4, base)

	var legacy ProcessSummaryResponse
	if rr := procGet(t, s, "/api/session/sA/processes/summary", nil, &legacy); rr.Code != http.StatusOK {
		t.Fatalf("summary: %d %s", rr.Code, rr.Body.String())
	}
	if !legacy.Legacy || legacy.Observed != 4 || legacy.Kept != 4 || legacy.Services == nil || legacy.Rollups == nil {
		t.Fatalf("legacy summary = %+v", legacy)
	}
	if legacy.Budget.PerToolCall != 200 || legacy.Budget.PerSession != 5000 || legacy.Budget.PerMinute != 300 {
		t.Fatalf("budget = %+v, want the config defaults", legacy.Budget)
	}

	// The capture path writes a service root, a kept service row, a rollup
	// and the stats.
	root := dashProcRun("svc", "", "sA", 900, "Docker Desktop.exe", "", base)
	root.CaptureClass, root.ServiceRootKey, root.Exited = "service_root", "svc", false
	child := dashProcRun("svc-1", "svc", "sA", 901, "docker.exe", "docker.exe stats", base.Add(time.Second))
	child.CaptureClass, child.ServiceRootKey = "service", "svc"
	key := proccapture.GroupKey{
		SessionID: "sA", BucketStart: proccapture.BucketStart(base, time.Minute), Kind: proccapture.GroupService,
		ParentProcessKey: "svc", ServiceRootKey: "svc", ExeBasename: "docker.exe", ArgvTemplateHash: "h",
	}
	delta := proccapture.Delta{
		Rollups: []proccapture.Rollup{{Key: key, Count: 30, CPUSumMs: 60, FirstSeen: base, LastSeen: base.Add(time.Minute), ExampleArgvPreview: "docker.exe stats"}},
		Stats:   map[string]proccapture.Stats{"sA": {Observed: 36, Kept: 4, ServiceKept: 2, ServiceRolledUp: 30, BudgetHits: 1}},
	}
	if _, err := st.PersistCapture(ctx, []procmodel.ProcessRun{root, child}, delta); err != nil {
		t.Fatal(err)
	}
	var sum ProcessSummaryResponse
	procGet(t, s, "/api/session/sA/processes/summary", nil, &sum)
	if sum.Legacy || sum.Observed != 36 || sum.ServiceRolledUp != 30 || !sum.Budget.Hit {
		t.Fatalf("summary = %+v", sum)
	}
	if sum.Observed != sum.Kept+sum.Folded+sum.RolledUp+sum.ServiceKept+sum.ServiceRolledUp+sum.Dropped {
		t.Fatalf("count invariant broken: %+v", sum)
	}
	if len(sum.Services) != 1 || sum.Services[0].RootKey != "svc" || sum.Services[0].Kept != 1 || sum.Services[0].RolledUp != 30 {
		t.Fatalf("services = %+v", sum.Services)
	}
	if len(sum.Rollups) != 1 || sum.Rollups[0].Count != 30 || sum.Rollups[0].GroupKind != "service" {
		t.Fatalf("rollups = %+v", sum.Rollups)
	}

	if rr := procGet(t, s, "/api/session/nope/processes/summary", nil, nil); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown session: %d", rr.Code)
	}
}

// TestProcessSummaryETag: the summary carries a strong ETag; a matching
// If-None-Match answers 304 with no body; a new row moves the ETag.
func TestProcessSummaryETag(t *testing.T) {
	s, _ := newTestServer(t)
	base := time.Now().UTC().Add(-20 * time.Minute)
	seedSessionRuns(t, s, 2, base)

	first := procGet(t, s, "/api/session/sA/processes/summary", nil, nil)
	etag := first.Header().Get("ETag")
	if first.Code != http.StatusOK || len(etag) < 3 || etag[0] != '"' {
		t.Fatalf("first: %d etag %q", first.Code, etag)
	}
	again := procGet(t, s, "/api/session/sA/processes/summary", map[string]string{"If-None-Match": etag}, nil)
	if again.Code != http.StatusNotModified || again.Body.Len() != 0 {
		t.Fatalf("conditional: %d body %q", again.Code, again.Body.String())
	}
	if got := again.Header().Get("ETag"); got != etag {
		t.Fatalf("304 etag %q, want %q", got, etag)
	}

	seedSessionRuns(t, s, 3, base) // adds r-002
	moved := procGet(t, s, "/api/session/sA/processes/summary", map[string]string{"If-None-Match": etag}, nil)
	if moved.Code != http.StatusOK || moved.Header().Get("ETag") == etag {
		t.Fatalf("after a new row: %d etag %q (was %q)", moved.Code, moved.Header().Get("ETag"), etag)
	}
}

// TestSessionProcessesWindow pins the windowed tree (plan §9.3): the newest
// limit rows by default, total stays the full count, the limit cap, to pages
// earlier rows, truncated, and a bad parameter is a 400.
func TestSessionProcessesWindow(t *testing.T) {
	s, _ := newTestServer(t)
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	seedSessionRuns(t, s, 12, base)

	var all SessionProcessResponse
	procGet(t, s, "/api/session/sA/processes", nil, &all)
	if all.Total != 12 || countTree(all.Roots) != 12 || all.Truncated || all.Window == nil ||
		all.Window.Limit != store.ProcessWindowDefaultLimit || all.Window.Returned != 12 {
		t.Fatalf("default window: total %d shown %d truncated %v window %+v", all.Total, countTree(all.Roots), all.Truncated, all.Window)
	}

	var page SessionProcessResponse
	procGet(t, s, "/api/session/sA/processes?limit=5", nil, &page)
	if page.Total != 12 || countTree(page.Roots) != 5 || !page.Truncated || page.Window.Returned != 5 {
		t.Fatalf("limit=5: total %d shown %d truncated %v", page.Total, countTree(page.Roots), page.Truncated)
	}
	// The parent r-000 is outside the window: its children are roots, not
	// dropped.
	if len(page.Roots) != 5 {
		t.Fatalf("limit=5 roots = %d, want the 5 orphaned children as roots", len(page.Roots))
	}
	oldest := page.Window.From
	if want := base.Add(7 * time.Second).Format(time.RFC3339); oldest != want {
		t.Fatalf("window from %q, want %q", oldest, want)
	}

	var earlier SessionProcessResponse
	to := base.Add(6 * time.Second).Format(time.RFC3339)
	procGet(t, s, "/api/session/sA/processes?limit=5&to="+to, nil, &earlier)
	if countTree(earlier.Roots) != 5 || !earlier.Truncated {
		t.Fatalf("to page: shown %d truncated %v", countTree(earlier.Roots), earlier.Truncated)
	}
	var last SessionProcessResponse
	procGet(t, s, "/api/session/sA/processes?limit=5&to="+base.Add(time.Second).Format(time.RFC3339), nil, &last)
	if countTree(last.Roots) != 2 || last.Truncated {
		t.Fatalf("first page: shown %d truncated %v", countTree(last.Roots), last.Truncated)
	}

	var capped SessionProcessResponse
	procGet(t, s, "/api/session/sA/processes?limit=99999", nil, &capped)
	if capped.Window.Limit != store.ProcessWindowMaxLimit {
		t.Fatalf("limit cap = %d", capped.Window.Limit)
	}
	for _, bad := range []string{"limit=abc", "from=yesterday", "to=2026-13-01", "since=x"} {
		if rr := procGet(t, s, "/api/session/sA/processes?"+bad, nil, nil); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", bad, rr.Code)
		}
	}
}

// TestProcessCaptureEstimate: the estimate replays stored runs under the
// proposed values; a bad key or value is a 400.
func TestProcessCaptureEstimate(t *testing.T) {
	s, _ := newTestServer(t)
	seedSessionRuns(t, s, 30, time.Now().UTC().Add(-2*time.Hour))

	var est proccapture.VolumeEstimate
	rr := procGet(t, s, "/api/process/capture/estimate?budget.per_tool_call=5&fold.extra_basenames=a.exe,b.exe", nil, &est)
	if rr.Code != http.StatusOK {
		t.Fatalf("estimate: %d %s", rr.Code, rr.Body.String())
	}
	if est.Basis.ObservedRows != 30 || est.Basis.Sessions != 1 {
		t.Fatalf("basis = %+v", est.Basis)
	}
	keys := map[string]bool{}
	for _, b := range est.BySetting {
		keys[b.Key] = true
	}
	if !keys["budget.per_tool_call"] || !keys["fold.extra_basenames"] {
		t.Fatalf("by_setting = %+v", est.BySetting)
	}
	for _, bad := range []string{"budget.per_tool_call=many", "nope=1", "unattributed.mode=keep", "enabled=perhaps"} {
		if rr := procGet(t, s, "/api/process/capture/estimate?"+bad, nil, nil); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", bad, rr.Code)
		}
	}
	// The basis is cached: a new row does not move it inside the TTL.
	seedSessionRuns(t, s, 31, time.Now().UTC().Add(-2*time.Hour))
	procGet(t, s, "/api/process/capture/estimate", nil, &est)
	if est.Basis.ObservedRows != 30 {
		t.Fatalf("cached basis rows = %d, want 30", est.Basis.ObservedRows)
	}
}

// TestWindowArchivedRuns pins the in-memory window used for the cold-archive
// fallback against the store's semantics.
func TestWindowArchivedRuns(t *testing.T) {
	base := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	var runs []store.ProcessRunRow
	for i := range 6 {
		at := base.Add(time.Duration(i) * time.Second)
		runs = append(runs, store.ProcessRunRow{ProcessKey: fmt.Sprint(i), PID: i, StartedAt: at, LastSeenAt: at})
	}
	for _, tc := range []struct {
		name      string
		w         store.ProcessRunWindow
		n         int
		truncated bool
	}{
		{"all", store.ProcessRunWindow{}, 6, false},
		{"limit", store.ProcessRunWindow{Limit: 2}, 2, true},
		{"to inclusive", store.ProcessRunWindow{To: base.Add(2 * time.Second)}, 3, false},
		{"from", store.ProcessRunWindow{From: base.Add(4 * time.Second)}, 2, true},
		{"since", store.ProcessRunWindow{Since: base.Add(5 * time.Second)}, 1, false},
	} {
		got, trunc := windowArchivedRuns(runs, tc.w)
		if len(got) != tc.n || trunc != tc.truncated {
			t.Errorf("%s: %d rows truncated %v, want %d %v", tc.name, len(got), trunc, tc.n, tc.truncated)
		}
	}
}

// TestProcessSummaryFindingsCountIncremental: a live session that gains rows
// between polls has its findings count updated from the new rows only, and
// the result always equals a full recount of the session.
func TestProcessSummaryFindingsCountIncremental(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	st := store.New(s.db())
	base := time.Now().UTC().Add(-time.Hour)
	persist := func(from, n int) {
		t.Helper()
		var runs []procmodel.ProcessRun
		for i := from; i < from+n; i++ {
			r := dashProcRun(fmt.Sprintf("f-%03d", i), "", "sA", 200+i, "tool", "tool run", base.Add(time.Duration(i)*time.Second))
			if i%3 == 0 {
				r.ExePath = "/tmp/build/tool"
			}
			runs = append(runs, r)
		}
		if _, err := st.PersistRuns(ctx, runs); err != nil {
			t.Fatalf("PersistRuns: %v", err)
		}
	}
	want := func() int {
		t.Helper()
		f, err := st.ProcessFindingsForSession(ctx, "sA")
		if err != nil {
			t.Fatal(err)
		}
		return len(f)
	}
	persist(0, 9)
	for _, step := range []int{9, 4, 0, 7} {
		if step > 0 {
			persist(countRuns(t, s, "sA"), step)
		}
		var sum ProcessSummaryResponse
		if rr := procGet(t, s, "/api/session/sA/processes/summary", nil, &sum); rr.Code != http.StatusOK {
			t.Fatalf("summary: %d %s", rr.Code, rr.Body.String())
		}
		if w := want(); sum.Findings != w || w == 0 {
			t.Fatalf("after +%d rows: findings = %d, full recount = %d", step, sum.Findings, w)
		}
	}
}

func countRuns(t *testing.T, s *Server, sess string) int {
	t.Helper()
	var n int
	if err := s.db().QueryRow(`SELECT COUNT(*) FROM process_runs WHERE session_id = ?`, sess).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
