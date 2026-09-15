package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
)

// TestResumeInfoDerivation pins the capability-shape dispatch of the
// session-detail `resume` block (session-attach Phase 3): a grounded
// ResumeNative tool → "native" + its launcher verb; a launchable non-native
// tool → "handoff"; a non-launchable non-native tool (and an unknown tool) →
// "none".
func TestResumeInfoDerivation(t *testing.T) {
	tests := []struct {
		tool    string
		kind    string
		subWant string
	}{
		{"claude-code", "native", "claude"},
		{"codex", "native", "codex"},
		{"cursor", "native", "cursor"}, // native `cursor-agent --resume <chatId>`, live-confirmed 2026-07-25
		{"openclaw", "handoff", ""},    // launchable, no grounded native resume surface
		{"cline", "none", ""},          // VS Code adapter: not launchable, no native resume
		{"totally-unknown-tool", "none", ""},
	}
	for _, tc := range tests {
		t.Run(tc.tool, func(t *testing.T) {
			got := resumeInfoForTool(tc.tool)
			if got.Kind != tc.kind {
				t.Errorf("resumeInfoForTool(%q).Kind = %q, want %q", tc.tool, got.Kind, tc.kind)
			}
			if got.Subcommand != tc.subWant {
				t.Errorf("resumeInfoForTool(%q).Subcommand = %q, want %q", tc.tool, got.Subcommand, tc.subWant)
			}
		})
	}
}

func TestResumeTranscriptPartitionUsesHandoff(t *testing.T) {
	if got := resumeInfoForSession("claude-code", "parent:agent:a123"); got.Kind != "handoff" || got.Subcommand != "" {
		t.Fatalf("subagent display ID must not reach native resume: %+v", got)
	}
	if got := resumeInfoForSession("claude-code", "parent"); got.Kind != "native" {
		t.Fatalf("parent lost resume: %+v", got)
	}
}

// newResumeTestServer builds a launch-wired dashboard over a fresh DB and
// returns both so a test can seed sessions.
func newResumeTestServer(t *testing.T, lm LaunchManager) *Server {
	t.Helper()
	tdir := t.TempDir()
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	s, err := New(Options{DB: database, LaunchManager: lm})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func seedResumeSession(t *testing.T, s *Server, id, tool, projectRoot string) {
	t.Helper()
	ctx := context.Background()
	// sessions.project_id is NOT NULL with an enforced FK, so a matching projects
	// row is always required; root_path may be "" (→ COALESCE resolves to "").
	var pid int64
	if err := s.opts.DB.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES (?, '2026-07-19T00:00:00Z') RETURNING id`,
		projectRoot).Scan(&pid); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	if _, err := s.opts.DB.ExecContext(ctx,
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, ?, '2026-07-19T00:00:00Z')`,
		id, pid, tool); err != nil {
		t.Fatalf("insert session: %v", err)
	}
}

func postSessionResume(t *testing.T, h http.Handler, sessionID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/session/"+sessionID+"/resume", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestResumePOSTDisabledWhenNilManager pins the honest 503 when the launcher is
// unwired.
func TestResumePOSTDisabledWhenNilManager(t *testing.T) {
	s := newResumeTestServer(t, nil)
	rec := postSessionResume(t, s.Handler(), "sess-1")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil manager: status = %d, want 503", rec.Code)
	}
}

// TestResumePOSTUnknownSession pins the 404 for a session id with no row.
func TestResumePOSTUnknownSession(t *testing.T) {
	s := newResumeTestServer(t, &fakeLaunchManager{})
	rec := postSessionResume(t, s.Handler(), "no-such-session")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown session: status = %d, want 404 (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestResumePOSTNonNativeIs409 pins the honest 409 for a tool with no grounded
// native resume, naming the Continue-in… fork fallback.
func TestResumePOSTNonNativeIs409(t *testing.T) {
	s := newResumeTestServer(t, &fakeLaunchManager{})
	seedResumeSession(t, s, "sess-fork", "openclaw", "")
	rec := postSessionResume(t, s.Handler(), "sess-fork")
	if rec.Code != http.StatusConflict {
		t.Fatalf("non-native resume: status = %d, want 409 (body=%s)", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "Continue in") {
		t.Errorf("409 body should name the Continue-in… fallback, got %q", body)
	}
}

// TestResumePOSTDuplicateLiveRunIs409 pins F5: a native resume is REFUSED with
// 409 when the session already has a live (non-exited) remote-sensitive run
// (resume OR attach), so repeated clicks can't spawn concurrent processes on the
// same transcript. An EXITED run of the same kind, and a live run of a DIFFERENT
// session, do NOT block.
func TestResumePOSTDuplicateLiveRunIs409(t *testing.T) {
	t.Run("live resume run blocks", func(t *testing.T) {
		lm := &fakeLaunchManager{
			snapshot: []LaunchInfo{
				{ID: "H1", Kind: "resume", SessionID: "sess-live", Subcommand: "claude"},
			},
		}
		s := newResumeTestServer(t, lm)
		seedResumeSession(t, s, "sess-live", "claude-code", "")
		rec := postSessionResume(t, s.Handler(), "sess-live")
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409 (body=%s)", rec.Code, rec.Body.String())
		}
		if body := rec.Body.String(); !strings.Contains(body, "already has a live terminal run") {
			t.Errorf("409 body should explain the live run, got %q", body)
		}
		// It never reached the spawner.
		if lm.lastResumeSpec.SessionID != "" {
			t.Error("duplicate resume must be refused BEFORE CreateResume")
		}
	})

	t.Run("live attach run blocks", func(t *testing.T) {
		lm := &fakeLaunchManager{
			snapshot: []LaunchInfo{
				{ID: "H2", Kind: "attach", SessionID: "sess-att", Subcommand: "claude"},
			},
		}
		s := newResumeTestServer(t, lm)
		seedResumeSession(t, s, "sess-att", "claude-code", "")
		rec := postSessionResume(t, s.Handler(), "sess-att")
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409 (body=%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("exited run does not block", func(t *testing.T) {
		lm := &fakeLaunchManager{
			snapshot: []LaunchInfo{
				{ID: "H3", Kind: "resume", SessionID: "sess-exit", Subcommand: "claude", Exited: true},
			},
		}
		s := newResumeTestServer(t, lm)
		seedResumeSession(t, s, "sess-exit", "claude-code", "")
		rec := postSessionResume(t, s.Handler(), "sess-exit")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (an exited run must not block) (body=%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("different session live run does not block", func(t *testing.T) {
		lm := &fakeLaunchManager{
			snapshot: []LaunchInfo{
				{ID: "H4", Kind: "resume", SessionID: "some-other-session", Subcommand: "claude"},
			},
		}
		s := newResumeTestServer(t, lm)
		seedResumeSession(t, s, "sess-target", "claude-code", "")
		rec := postSessionResume(t, s.Handler(), "sess-target")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (a different session's run must not block) (body=%s)", rec.Code, rec.Body.String())
		}
	})
}

// concurrentResumeLM is a thread-safe LaunchManager that REGISTERS a live resume
// run when CreateResume is called (mirroring the real adapter, which records +
// maps the run before Spawn returns) and reports it from Snapshot. A small delay
// inside CreateResume widens the check-then-spawn race window so a missing
// single-flight would let two concurrent POSTs both spawn.
type concurrentResumeLM struct {
	*fakeLaunchManager
	mu     sync.Mutex
	live   []LaunchInfo
	spawns int
}

func (m *concurrentResumeLM) Snapshot() []LaunchInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]LaunchInfo(nil), m.live...)
}

func (m *concurrentResumeLM) CreateResume(spec ResumeLaunchSpec) (string, string, error) {
	time.Sleep(20 * time.Millisecond) // widen the race window
	m.mu.Lock()
	m.spawns++
	n := m.spawns
	m.live = append(m.live, LaunchInfo{ID: fmt.Sprintf("R%d", n), Kind: "resume", SessionID: spec.SessionID})
	m.mu.Unlock()
	return fmt.Sprintf("RESUME-%d", n), fmt.Sprintf("RUN-%d", n), nil
}

// TestResumePOSTConcurrentSingleFlight pins R2-3: two concurrent POSTs to resume
// the SAME session must produce EXACTLY one spawn — the other is refused 409 by
// the per-session single-flight around the check+spawn. Without it, both POSTs
// observe no live run and both spawn a tool process on the same transcript.
func TestResumePOSTConcurrentSingleFlight(t *testing.T) {
	lm := &concurrentResumeLM{fakeLaunchManager: &fakeLaunchManager{}}
	s := newResumeTestServer(t, lm)
	seedResumeSession(t, s, "sess-race", "claude-code", "")
	h := s.Handler()

	const n = 2
	codes := make([]int, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			codes[i] = postSessionResume(t, h, "sess-race").Code
		}(i)
	}
	wg.Wait()

	var ok, conflict int
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusConflict:
			conflict++
		default:
			t.Fatalf("unexpected status %d (want 200 or 409)", c)
		}
	}
	if ok != 1 || conflict != 1 {
		t.Fatalf("concurrent resume: %d×200 %d×409, want exactly 1×200 + 1×409", ok, conflict)
	}
	lm.mu.Lock()
	spawns := lm.spawns
	lm.mu.Unlock()
	if spawns != 1 {
		t.Fatalf("CreateResume spawned %d times, want exactly 1 (single-flight)", spawns)
	}
}

// TestResumePOSTEmitsResumeAuditRow pins F4: a successful /resume POST that is
// NEVER attached over the websocket still writes EXACTLY ONE metadata-only
// terminal_resume remote_audit row at spawn time — carrying the run id + handle
// + tool, never argv/env/content. Without this a caller that resumes but never
// attaches produces a real process with no audit trail.
func TestResumePOSTEmitsResumeAuditRow(t *testing.T) {
	lm := &fakeLaunchManager{}
	s := newResumeTestServer(t, lm)
	seedResumeSession(t, s, "sess-audit", "claude-code", "/home/dev/proj")

	rec := postSessionResume(t, s.Handler(), "sess-audit")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	ctx := context.Background()
	// The spawn audit is DETACHED (F3) so it lands asynchronously — POLL for it
	// rather than reading once right after the (now non-blocking) resume POST.
	var count int
	var sessionID, principal, route, detail string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		rows, err := s.opts.DB.QueryContext(ctx,
			`SELECT session_id, principal, route, detail FROM remote_audit WHERE kind = 'terminal_resume'`)
		if err != nil {
			t.Fatalf("query remote_audit: %v", err)
		}
		count = 0
		for rows.Next() {
			count++
			if err := rows.Scan(&sessionID, &principal, &route, &detail); err != nil {
				rows.Close()
				t.Fatal(err)
			}
		}
		rows.Close()
		if count >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if count != 1 {
		t.Fatalf("expected exactly one terminal_resume row (no ws attach), got %d", count)
	}
	if principal != "execute" || detail != "claude-code" {
		t.Errorf("terminal_resume row principal=%q detail=%q, want execute/claude-code", principal, detail)
	}
	if sessionID == "" || route == "" {
		t.Errorf("terminal_resume row must carry run id (session_id=%q) + handle (route=%q)", sessionID, route)
	}
}

// TestResumePOSTProjectRootDeniedIs403 pins F6: an allow-list rejection of the
// session's stored project root is an authorization refusal (403), not malformed
// input (400) — the project root is server-loaded, never client-supplied.
func TestResumePOSTProjectRootDeniedIs403(t *testing.T) {
	lm := &fakeLaunchManager{resumeErr: ErrLaunchProjectRootDenied}
	s := newResumeTestServer(t, lm)
	seedResumeSession(t, s, "sess-denied", "claude-code", "/not/allowed")
	rec := postSessionResume(t, s.Handler(), "sess-denied")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (project-root policy refusal) (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestResumePOSTNativeHappyPath pins the full native resume: the handler loads
// tool + project root, composes the resume tail via integration.ResumeArgs, and
// spawns through CreateResume — the fake captures the exact ExtraArgs + project
// root, and the response carries the token + run_id wire shape.
func TestResumePOSTNativeHappyPath(t *testing.T) {
	lm := &fakeLaunchManager{}
	s := newResumeTestServer(t, lm)
	seedResumeSession(t, s, "sess-42", "claude-code", "/home/dev/proj")

	rec := postSessionResume(t, s.Handler(), "sess-42")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var out struct {
		Token      string `json:"token"`
		RunID      string `json:"run_id"`
		Subcommand string `json:"subcommand"`
		SessionID  string `json:"session_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Token == "" || out.RunID == "" {
		t.Errorf("response missing token/run_id: %+v", out)
	}
	if out.Subcommand != "claude" || out.SessionID != "sess-42" {
		t.Errorf("response = %+v, want subcommand=claude session_id=sess-42", out)
	}
	// The fake captured the server-derived spawn request.
	spec := lm.lastResumeSpec
	if spec.Tool != "claude-code" || spec.Subcommand != "claude" {
		t.Errorf("resume spec tool/subcommand = %q/%q, want claude-code/claude", spec.Tool, spec.Subcommand)
	}
	if spec.ProjectRoot != "/home/dev/proj" {
		t.Errorf("resume spec ProjectRoot = %q, want /home/dev/proj", spec.ProjectRoot)
	}
	if spec.SessionID != "sess-42" {
		t.Errorf("resume spec SessionID = %q, want sess-42", spec.SessionID)
	}
	if len(spec.ExtraArgs) != 2 || spec.ExtraArgs[0] != "--resume" || spec.ExtraArgs[1] != "sess-42" {
		t.Errorf("resume spec ExtraArgs = %v, want [--resume sess-42]", spec.ExtraArgs)
	}
}
