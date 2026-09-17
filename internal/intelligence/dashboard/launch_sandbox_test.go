package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
)

// --- fakes ---

// fakeSandboxProber is a caller-configured SandboxProber (internal/intelligence/dashboard/sandbox.go).
// It always returns the same avail value regardless of context — enough for
// the fail-closed/fail-soft table this suite pins.
type fakeSandboxProber struct {
	avail SandboxAvailability
}

func (f *fakeSandboxProber) ProbeSandbox(ctx context.Context) SandboxAvailability {
	return f.avail
}

// countingLaunchManager wraps fakeLaunchManager (launch_test.go) to count
// CreateFresh invocations. The B9 plan's mutation proof #1 ("no unsandboxed
// fallback path exists in the code") is pinned here as createFreshCalls==0
// on every rejected sandbox request — a stronger assertion than the HTTP
// status alone, which would also pass if the handler validated correctly
// but then called CreateFresh anyway on a code path that later errored out.
type countingLaunchManager struct {
	*fakeLaunchManager
	createFreshCalls int
}

func (m *countingLaunchManager) CreateFresh(spec FreshLaunchSpec) (string, error) {
	m.createFreshCalls++
	return m.fakeLaunchManager.CreateFresh(spec)
}

// --- helpers ---

// newLaunchTestServerWithSandbox is newLaunchTestServer (launch_test.go)
// plus a caller-supplied Options.SandboxProber seam. Nil prober behaves
// exactly like newLaunchTestServer (the seam stays unset — the honest
// disabled state, A5).
func newLaunchTestServerWithSandbox(t *testing.T, lm LaunchManager, prober SandboxProber) *Server {
	t.Helper()
	tdir := t.TempDir()
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	s, err := New(Options{DB: database, LaunchManager: lm, SandboxProber: prober})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// postTerminalLaunchSandbox POSTs an arbitrary terminalLaunchRequest — the
// package's own postTerminalLaunch (launch_test.go) only carries
// tool/project_root, not the B9 sandbox fields this suite needs to vary.
func postTerminalLaunchSandbox(t *testing.T, h http.Handler, body terminalLaunchRequest) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/terminal/launch", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func getTerminalSandboxProbe(t *testing.T, h http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/terminal/sandbox", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// availableProbe is a stock "everything works" SandboxAvailability used by
// the tests below that only want to fail one specific check.
func availableProbe() SandboxAvailability {
	return SandboxAvailability{
		Available: true,
		Verdict:   "available",
		Backend:   "bwrap",
		Sources: []SandboxSourceAvail{
			{ID: "live", Available: true},
			{ID: "clone-remote", Available: true},
		},
		Tools: map[string]SandboxToolAvail{
			"claude-code": {Available: true},
		},
	}
}

// --- handleTerminalLaunch: fail-closed sandbox validation ---

// TestTerminalLaunchRejectsSandboxWhenSeamNil is the A5 proof (plan §12
// amendment A5): a nil Options.SandboxProber must refuse a sandbox=true
// launch with 501, and must NEVER fall through to an unsandboxed
// CreateFresh call.
func TestTerminalLaunchRejectsSandboxWhenSeamNil(t *testing.T) {
	lm := &countingLaunchManager{fakeLaunchManager: &fakeLaunchManager{}}
	s := newLaunchTestServer(t, lm) // SandboxProber left unset (nil)

	rec := postTerminalLaunchSandbox(t, s.Handler(), terminalLaunchRequest{
		Tool: "claude-code", ProjectRoot: "/repo", Sandbox: true,
	})

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501 (body=%s)", rec.Code, rec.Body.String())
	}
	if lm.createFreshCalls != 0 {
		t.Fatalf("createFreshCalls = %d, want 0 — CreateFresh must not be called when the sandbox seam is nil", lm.createFreshCalls)
	}
}

// TestTerminalLaunchRejectsSandboxWhenBackendMissing covers the probed
// (non-nil seam) unavailable case: verdict "backend_missing" must still map
// to 501 and still refuse to call CreateFresh.
func TestTerminalLaunchRejectsSandboxWhenBackendMissing(t *testing.T) {
	lm := &countingLaunchManager{fakeLaunchManager: &fakeLaunchManager{}}
	prober := &fakeSandboxProber{avail: SandboxAvailability{
		Available: false,
		Verdict:   "backend_missing",
		Reason:    "bwrap not found on PATH",
	}}
	s := newLaunchTestServerWithSandbox(t, lm, prober)

	rec := postTerminalLaunchSandbox(t, s.Handler(), terminalLaunchRequest{
		Tool: "claude-code", ProjectRoot: "/repo", Sandbox: true,
	})

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501 (body=%s)", rec.Code, rec.Body.String())
	}
	if lm.createFreshCalls != 0 {
		t.Fatalf("createFreshCalls = %d, want 0", lm.createFreshCalls)
	}
}

// TestTerminalLaunchRejectsSandboxWhenDisabledByConfig pins the one verdict
// that maps to 403 rather than 501 (an operator authorization refusal, not
// a capability gap — see the sandboxVerdictStatus table doc comment).
func TestTerminalLaunchRejectsSandboxWhenDisabledByConfig(t *testing.T) {
	lm := &countingLaunchManager{fakeLaunchManager: &fakeLaunchManager{}}
	prober := &fakeSandboxProber{avail: SandboxAvailability{
		Available: false,
		Verdict:   "disabled_by_config",
		Reason:    "[terminal.sandbox].enabled is false",
	}}
	s := newLaunchTestServerWithSandbox(t, lm, prober)

	rec := postTerminalLaunchSandbox(t, s.Handler(), terminalLaunchRequest{
		Tool: "claude-code", ProjectRoot: "/repo", Sandbox: true,
	})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
	if lm.createFreshCalls != 0 {
		t.Fatalf("createFreshCalls = %d, want 0", lm.createFreshCalls)
	}
}

// TestTerminalLaunchRejectsUnknownWorkspaceSource proves workspace_source is
// re-derived by MEMBERSHIP against the probed Sources list server-side, not
// trusted verbatim from the client.
func TestTerminalLaunchRejectsUnknownWorkspaceSource(t *testing.T) {
	lm := &countingLaunchManager{fakeLaunchManager: &fakeLaunchManager{}}
	prober := &fakeSandboxProber{avail: availableProbe()}
	s := newLaunchTestServerWithSandbox(t, lm, prober)

	rec := postTerminalLaunchSandbox(t, s.Handler(), terminalLaunchRequest{
		Tool: "claude-code", ProjectRoot: "/repo", Sandbox: true, WorkspaceSource: "bogus-source",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if lm.createFreshCalls != 0 {
		t.Fatalf("createFreshCalls = %d, want 0", lm.createFreshCalls)
	}
}

// TestTerminalLaunchRejectsSandboxLiveSourceWithoutProjectRoot pins: a
// sandboxed launch against the "live" workspace source (the default when
// workspace_source is empty) needs a project directory to sandbox — an
// empty one is a 400, not a launch against an undefined workspace.
func TestTerminalLaunchRejectsSandboxLiveSourceWithoutProjectRoot(t *testing.T) {
	lm := &countingLaunchManager{fakeLaunchManager: &fakeLaunchManager{}}
	prober := &fakeSandboxProber{avail: availableProbe()}
	s := newLaunchTestServerWithSandbox(t, lm, prober)

	rec := postTerminalLaunchSandbox(t, s.Handler(), terminalLaunchRequest{
		Tool: "claude-code", Sandbox: true, // no ProjectRoot, no WorkspaceSource (defaults to "live")
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if lm.createFreshCalls != 0 {
		t.Fatalf("createFreshCalls = %d, want 0", lm.createFreshCalls)
	}
}

// TestTerminalLaunchRejectsSandboxUnmappedTool pins the per-tool check: a
// tool absent from av.Tools (no grounded SandboxSpec registry row) cannot be
// sandboxed, regardless of everything else being available.
func TestTerminalLaunchRejectsSandboxUnmappedTool(t *testing.T) {
	lm := &countingLaunchManager{fakeLaunchManager: &fakeLaunchManager{}}
	prober := &fakeSandboxProber{avail: SandboxAvailability{
		Available: true,
		Verdict:   "available",
		Sources:   []SandboxSourceAvail{{ID: "live", Available: true}},
		Tools:     map[string]SandboxToolAvail{}, // "codex" has no grounded row here
	}}
	s := newLaunchTestServerWithSandbox(t, lm, prober)

	rec := postTerminalLaunchSandbox(t, s.Handler(), terminalLaunchRequest{
		Tool: "codex", ProjectRoot: "/repo", Sandbox: true,
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if lm.createFreshCalls != 0 {
		t.Fatalf("createFreshCalls = %d, want 0", lm.createFreshCalls)
	}
}

// TestTerminalLaunchSandboxFalseUnchanged is the regression pin: an ordinary
// (sandbox:false) launch must behave byte-identically to before this unit's
// changes, even with Options.SandboxProber left nil. This also proves the
// nil-seam check is scoped inside `if body.Sandbox` and never blocks a plain
// launch.
func TestTerminalLaunchSandboxFalseUnchanged(t *testing.T) {
	lm := &fakeLaunchManager{}
	s := newLaunchTestServer(t, lm) // SandboxProber left unset (nil)

	rec := postTerminalLaunchSandbox(t, s.Handler(), terminalLaunchRequest{
		Tool: "codex", Sandbox: false,
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var out terminalLaunchResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rec.Body.String())
	}
	if len(out.Token) == 0 || out.Tool != "codex" || out.Subcommand != "codex" {
		t.Fatalf("response = %+v, want a populated token/tool=codex/subcommand=codex", out)
	}
	if lm.lastFreshSpec.Sandbox {
		t.Fatalf("fresh spec Sandbox = true, want false")
	}
}

// TestTerminalLaunchSandboxSuccessForwardsWorkspaceFields is the happy path:
// once every fail-closed check passes, the handler forwards Sandbox and the
// three workspace fields to FreshLaunchSpec verbatim (the "clone-remote"
// source does NOT require ProjectRoot — only "live" does).
func TestTerminalLaunchSandboxSuccessForwardsWorkspaceFields(t *testing.T) {
	lm := &fakeLaunchManager{}
	prober := &fakeSandboxProber{avail: availableProbe()}
	s := newLaunchTestServerWithSandbox(t, lm, prober)

	rec := postTerminalLaunchSandbox(t, s.Handler(), terminalLaunchRequest{
		Tool: "claude-code", Sandbox: true, WorkspaceSource: "clone-remote",
		WorkspaceRemote: "https://example.com/repo.git", WorkspaceBranch: "feature",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if !lm.lastFreshSpec.Sandbox ||
		lm.lastFreshSpec.WorkspaceSource != "clone-remote" ||
		lm.lastFreshSpec.WorkspaceRemote != "https://example.com/repo.git" ||
		lm.lastFreshSpec.WorkspaceBranch != "feature" {
		t.Fatalf("fresh spec = %+v, want Sandbox/WorkspaceSource/WorkspaceRemote/WorkspaceBranch forwarded", lm.lastFreshSpec)
	}
}

// --- GET /api/terminal/sandbox: fail-soft probe endpoint ---

// TestTerminalSandboxProbeDisabledWhenSeamNil mirrors the B5
// /api/terminal/launch/models fail-soft contract: a nil seam is a 200 with
// an honest disabled verdict, never an error status.
func TestTerminalSandboxProbeDisabledWhenSeamNil(t *testing.T) {
	s := newLaunchTestServer(t, &fakeLaunchManager{}) // SandboxProber left unset (nil)

	rec := getTerminalSandboxProbe(t, s.Handler())

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var out SandboxAvailability
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rec.Body.String())
	}
	if out.Available {
		t.Fatalf("available = true, want false when SandboxProber is nil")
	}
	if out.Verdict != "disabled_by_config" {
		t.Fatalf("verdict = %q, want disabled_by_config", out.Verdict)
	}
	if out.Reason == "" {
		t.Fatalf("reason is empty, want an honest explanation of the disabled state")
	}
}

// TestTerminalSandboxProbeReturnsSeamResult proves the endpoint is a
// pass-through of the injected SandboxProber's result when the seam is
// configured — no daemon-side reinterpretation of the verdict/fields.
func TestTerminalSandboxProbeReturnsSeamResult(t *testing.T) {
	prober := &fakeSandboxProber{avail: SandboxAvailability{
		Available:      true,
		Verdict:        "available",
		Backend:        "bwrap",
		BackendVersion: "0.8.0",
		HomeMode:       "tmpfs",
		DefaultOn:      true,
		Sources:        []SandboxSourceAvail{{ID: "live", Available: true}},
		Tools:          map[string]SandboxToolAvail{"claude-code": {Available: true}},
	}}
	s := newLaunchTestServerWithSandbox(t, &fakeLaunchManager{}, prober)

	rec := getTerminalSandboxProbe(t, s.Handler())

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var out SandboxAvailability
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rec.Body.String())
	}
	if !out.Available || out.Backend != "bwrap" || out.BackendVersion != "0.8.0" || out.HomeMode != "tmpfs" || !out.DefaultOn {
		t.Fatalf("out = %+v, want the probe's fields passed through verbatim", out)
	}
}

func TestTerminalSandboxProbeRejectsNonGet(t *testing.T) {
	s := newLaunchTestServer(t, &fakeLaunchManager{})
	req := httptest.NewRequest(http.MethodPost, "/api/terminal/sandbox", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405 (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestTerminalSandboxProbeVerdictTable is the one table over the closed
// verdict vocabulary the probe endpoint + the fail-closed launch gate share
// (sandbox.go's Verdict* constants plus the platform verdicts
// internal/sandbox owns). One row per verdict, each asserting BOTH halves of
// the contract at once: the GET is always a fail-SOFT 200 carrying the
// verdict verbatim, and the POST is fail-CLOSED with the status
// sandboxVerdictStatus maps that verdict to — never a launch.
//
// The two rows that matter most to this arc are disabled_by_config and
// runtime_init_failed. They used to be ONE string: an enabled-but-broken
// sandbox reported "disabled by config", which sent the operator to flip a
// switch that was already on. They are now distinct verdicts with distinct
// copy, and runtime_init_failed — being unknown to sandboxVerdictStatus —
// lands on that table's fail-closed 501 floor rather than on a permissive
// default.
func TestTerminalSandboxProbeVerdictTable(t *testing.T) {
	cases := []struct {
		name       string
		avail      SandboxAvailability
		wantStatus int // the POST /api/terminal/launch refusal status
	}{
		{
			name: "disabled_by_config",
			avail: SandboxAvailability{
				Verdict: VerdictDisabledByConfig,
				Reason:  "[terminal.sandbox].enabled is false on this daemon",
			},
			// An operator refusal, not a capability gap.
			wantStatus: http.StatusForbidden,
		},
		{
			name: "runtime_init_failed",
			avail: SandboxAvailability{
				Verdict: VerdictRuntimeInitFailed,
				Reason:  `newSandboxRuntime: create workspaces dir: mkdir /nope: permission denied`,
			},
			// Unknown to sandboxVerdictStatus -> the fail-closed 501 floor.
			wantStatus: http.StatusNotImplemented,
		},
		{
			name:       "backend_missing",
			avail:      SandboxAvailability{Verdict: "backend_missing", Reason: "bwrap not found on PATH"},
			wantStatus: http.StatusNotImplemented,
		},
		{
			name:       "backend_too_old",
			avail:      SandboxAvailability{Verdict: "backend_too_old", Reason: "bwrap 0.3.3 is older than the 0.4.0 floor"},
			wantStatus: http.StatusNotImplemented,
		},
		{
			name:       "userns_denied",
			avail:      SandboxAvailability{Verdict: "userns_denied", Reason: "kernel.unprivileged_userns_clone is 0"},
			wantStatus: http.StatusNotImplemented,
		},
		{
			name:       "unsupported_platform",
			avail:      SandboxAvailability{Verdict: "unsupported_platform", Reason: "bwrap sandboxing is Linux-only"},
			wantStatus: http.StatusNotImplemented,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lm := &countingLaunchManager{fakeLaunchManager: &fakeLaunchManager{}}
			s := newLaunchTestServerWithSandbox(t, lm, &fakeSandboxProber{avail: tc.avail})

			// Half 1: the probe endpoint is fail-SOFT and verbatim.
			rec := getTerminalSandboxProbe(t, s.Handler())
			if rec.Code != http.StatusOK {
				t.Fatalf("probe status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
			}
			var out SandboxAvailability
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatalf("decode probe: %v (body=%s)", err, rec.Body.String())
			}
			if out.Available {
				t.Errorf("available = true, want false for verdict %q", tc.avail.Verdict)
			}
			if out.Verdict != tc.avail.Verdict {
				t.Errorf("verdict = %q, want %q", out.Verdict, tc.avail.Verdict)
			}
			if out.Reason != tc.avail.Reason {
				t.Errorf("reason = %q, want the seam's reason %q verbatim", out.Reason, tc.avail.Reason)
			}

			// Half 2: the launch gate is fail-CLOSED, with no CreateFresh.
			post := postTerminalLaunchSandbox(t, s.Handler(), terminalLaunchRequest{
				Tool: "claude-code", ProjectRoot: "/repo", Sandbox: true,
			})
			if post.Code != tc.wantStatus {
				t.Errorf("launch status = %d, want %d (body=%s)", post.Code, tc.wantStatus, post.Body.String())
			}
			if !strings.Contains(post.Body.String(), tc.avail.Verdict) {
				t.Errorf("launch refusal %q does not name the verdict %q", post.Body.String(), tc.avail.Verdict)
			}
			if lm.createFreshCalls != 0 {
				t.Errorf("createFreshCalls = %d, want 0", lm.createFreshCalls)
			}
		})
	}
}
