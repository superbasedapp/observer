package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// armLocalWrite gives a test request what the SPA sends on every owner-local
// write: a JSON content type and a matching double-submit confirm token
// (review M3-05).
func armLocalWrite(r *http.Request) *http.Request {
	if r.Header.Get("Content-Type") == "" {
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set(remoteConfirmHeader, "tok")
	r.AddCookie(&http.Cookie{Name: remoteConfirmCookie, Value: "tok"})
	return r
}

// TestNewMutationRoutesRequireConfirmToken pins review M3-05: every write
// route the CLI-only-flows and request-grants arcs added refuses a request
// that does not echo the owner-local confirm token, before it acts.
func TestNewMutationRoutesRequireConfirmToken(t *testing.T) {
	var called atomic.Bool
	fake := func(_ context.Context, _ []string, _ func([]byte)) (int, error) {
		called.Store(true)
		return 0, nil
	}
	server := newServerWithFakeExec(t, fake)
	cases := []struct{ method, path, body string }{
		{http.MethodPost, "/api/jobs/score", ""},
		{http.MethodPost, "/api/jobs/summarize", ""},
		{http.MethodPost, "/api/jobs/mcp-wrap", ""},
		{http.MethodPost, "/api/jobs/doctor-integrity", ""},
		{http.MethodPost, "/api/jobs/doctor-integrity/cancel", `{"job_id":"x"}`},
		{http.MethodPost, "/api/jobs/reclaim-cleanup", ""},
		{http.MethodPost, "/api/jobs/reclaim-cleanup/cancel", `{"job_id":"x"}`},
		{http.MethodPost, "/api/benchmarks/run", `{"spec":"name = \"x\""}`},
		{http.MethodPost, "/api/benchmarks/delete", `{"run_id":"r1"}`},
		{http.MethodPost, "/api/setup/codex", `{"undo":true,"dry_run":true}`},
		{http.MethodPost, "/api/setup/claude", `{"undo":true,"dry_run":true}`},
		// T-421: the wizard's hooks / MCP removal (the `observer uninstall`
		// removal per tool) carries the token too, even as a dry run.
		{http.MethodPost, "/api/setup/hooks", `{"tool":"claude-code","undo":true,"dry_run":true}`},
		{http.MethodPost, "/api/setup/mcp", `{"tool":"claude-code","undo":true,"dry_run":true}`},
		{http.MethodPost, "/api/setup/windows-homes/apply", `{"target":"codex-windows","home":"/mnt/c/Users/x","dry_run":true}`},
		{http.MethodPost, "/api/config/adopt-defaults", `{"adapters":[]}`},
		{http.MethodPost, "/api/config/profiles", `{"name":"p1"}`},
		{http.MethodPatch, "/api/config/profiles/p1", `{"key":"k","value":"v"}`},
		{http.MethodDelete, "/api/config/profiles/p1", ""},
		{http.MethodPut, "/api/config/profile-assignments", `{"target":"tool:cline","profile":"codex-safe"}`},
		{http.MethodDelete, "/api/config/profile-assignments", `{"target":"tool:cline"}`},
		{http.MethodPut, "/api/config/project-profiles", `{"root":"/r","target":"default","profile":"codex-safe","preview":true}`},
		{http.MethodDelete, "/api/config/project-profiles", `{"root":"/r","target":"default","preview":true}`},
		{http.MethodPost, "/api/requests", `{"request":{}}`},
		{http.MethodPost, "/api/requests/7/withdraw", ""},
		{http.MethodPost, "/api/requests/queued/7/cancel", ""},
		// T-496: the reputation lookup (one outbound registry request).
		{http.MethodPost, "/api/guard/mcp/reputation", `{"package":"left-pad"}`},
		// T-530: the notification bell's read / dismiss write.
		{http.MethodPost, "/api/notifications/state", `{"ids":["x"],"action":"read"}`},
		// T-922: the first-run view's seen write.
		{http.MethodPost, "/api/firstrun/seen", `{"seen":true}`},
		// T-854: every messages write carries the token.
		{http.MethodPost, "/api/messages", `{"thread_id":"t1","body":"x"}`},
		{http.MethodPost, "/api/messages/threads/t1/read", ""},
		{http.MethodPost, "/api/messages/7/ack", ""},
		{http.MethodPost, "/api/messages/outbox/c1/retry", ""},
		{http.MethodPost, "/api/messages/outbox/c1/discard", ""},
		// T-537: the exporter wiring step, preview and write alike.
		{http.MethodPost, "/api/setup/telemetry", `{"tool":"qwen-code","dry_run":true}`},
		{http.MethodPost, "/api/setup/telemetry", `{"tool":"qwen-code","undo":true,"dry_run":true}`},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			for _, variant := range []string{"no token", "mismatched token"} {
				r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
				r.Header.Set("Content-Type", "application/json")
				if variant == "mismatched token" {
					r.Header.Set(remoteConfirmHeader, "tok")
					r.AddCookie(&http.Cookie{Name: remoteConfirmCookie, Value: "other"})
				}
				rr := httptest.NewRecorder()
				server.Handler().ServeHTTP(rr, r)
				if answeredCompiledOut(rr.Code, rr.Body.Bytes()) {
					// The route's component is compiled out of this build:
					// its stub refuses with 404 not_compiled before acting.
					continue
				}
				if rr.Code != http.StatusForbidden {
					t.Fatalf("%s: %s %s = %d %s, want 403", variant, tc.method, tc.path, rr.Code, rr.Body.String())
				}
			}
		})
	}
	time.Sleep(50 * time.Millisecond)
	if called.Load() {
		t.Fatal("a refused job POST still ran the CLI")
	}
}

// TestCommandJobListMintsConfirmToken: the job list (the GET every job card
// loads on mount) sets the double-submit cookie and returns its value.
func TestCommandJobListMintsConfirmToken(t *testing.T) {
	server := newServerWithFakeExec(t, newFakeExec(&fakeExecResult{}))
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/jobs?mode=confirm-mint", nil))
	var body struct {
		ConfirmToken string `json:"confirm_token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || body.ConfirmToken == "" {
		t.Fatalf("GET /api/jobs = %d %s", rr.Code, rr.Body.String())
	}
	minted := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == remoteConfirmCookie && c.Value == body.ConfirmToken {
			minted = true
		}
	}
	if !minted {
		t.Fatal("the job list did not set the confirm cookie")
	}
}

// TestCommandJobsConcealedWithTheirPage pins review M3-04's governance half:
// a job whose owning page or tab the organization hides is neither listed nor
// polled (its earlier output included), while other jobs still are.
func TestCommandJobsConcealedWithTheirPage(t *testing.T) {
	server := newServerWithFakeExec(t, newFakeExec(&fakeExecResult{out: []byte("~/.claude.json: wrapped\n")}))
	start := func(name string) string {
		t.Helper()
		rr := httptest.NewRecorder()
		server.Handler().ServeHTTP(rr, armLocalWrite(httptest.NewRequest(http.MethodPost, "/api/jobs/"+name, nil)))
		var resp struct {
			JobID string `json:"job_id"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil || resp.JobID == "" {
			t.Fatalf("POST %s = %d %s", name, rr.Code, rr.Body.String())
		}
		return resp.JobID
	}
	mcpID := start("mcp-doctor")
	scoreID := start("score")
	pollCommandJob(t, server, mcpID)
	pollCommandJob(t, server, scoreID)

	server.opts.Governance = governedProvider(t, []string{"security/mcp"}, nil, nil, nil)
	rr := httptest.NewRecorder()
	server.handleCommandJobs(rr, httptest.NewRequest(http.MethodGet, "/api/jobs", nil))
	var list struct {
		Jobs []backfillJob `json:"jobs"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Jobs) != 1 || list.Jobs[0].ID != scoreID {
		t.Fatalf("list under a hidden MCP tab = %+v, want only the score job", list.Jobs)
	}
	rr = httptest.NewRecorder()
	server.handleCommandJobs(rr, httptest.NewRequest(http.MethodGet, "/api/jobs/"+mcpID, nil))
	if rr.Code != http.StatusNotFound || strings.Contains(rr.Body.String(), "wrapped") {
		t.Fatalf("poll of a hidden tab's job = %d %s, want 404 without its output", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	server.handleCommandJobs(rr, httptest.NewRequest(http.MethodGet, "/api/jobs/"+scoreID, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("poll of a visible page's job = %d", rr.Code)
	}
}
