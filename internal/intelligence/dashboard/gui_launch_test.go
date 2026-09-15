package dashboard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// anyAdvertisedGUIID returns one advertised GUI launch id from the live
// registry, or skips. The GUI ROWS are populated by a sibling ticket (T2.1), so
// these endpoint tests key off whatever the registry advertises rather than
// hardcoding an id that may not exist yet.
func anyAdvertisedGUIID(t *testing.T) string {
	t.Helper()
	for _, g := range integration.GUILaunchables() {
		if g.Advertised() {
			return g.Spec.ID
		}
	}
	t.Skip("no advertised GUI launch rows in the registry yet (populated by T2.1)")
	return ""
}

func postGUILaunch(t *testing.T, h http.Handler, body terminalLaunchRequest) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/terminal/launch", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestTerminalLaunchKindAbsentTakesThePTYPath is THE regression guard for the
// additive-dispatch invariant: a request with no `kind` must reach CreateFresh
// exactly as before, and must never touch the GUI seam.
func TestTerminalLaunchKindAbsentTakesThePTYPath(t *testing.T) {
	lm := &fakeLaunchManager{}
	s := newLaunchTestServer(t, lm)
	rec := postGUILaunch(t, s.Handler(), terminalLaunchRequest{Tool: "claude-code"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if lm.lastFreshSpec.Tool != "claude-code" {
		t.Errorf("fresh spec = %+v, want the PTY path", lm.lastFreshSpec)
	}
	if lm.lastGUISpec.ID != "" {
		t.Errorf("a kindless request reached the GUI seam: %+v", lm.lastGUISpec)
	}
}

// TestTerminalLaunchExplicitTerminalKindTakesThePTYPath pins that the explicit
// spelling behaves identically to the absent one.
func TestTerminalLaunchExplicitTerminalKindTakesThePTYPath(t *testing.T) {
	lm := &fakeLaunchManager{}
	s := newLaunchTestServer(t, lm)
	rec := postGUILaunch(t, s.Handler(), terminalLaunchRequest{Kind: "terminal", Tool: "claude-code"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if lm.lastFreshSpec.Tool != "claude-code" || lm.lastGUISpec.ID != "" {
		t.Errorf("fresh=%+v gui=%+v, want the PTY path only", lm.lastFreshSpec, lm.lastGUISpec)
	}
}

func TestTerminalLaunchUnknownKindIsRejected(t *testing.T) {
	lm := &fakeLaunchManager{}
	s := newLaunchTestServer(t, lm)
	rec := postGUILaunch(t, s.Handler(), terminalLaunchRequest{Kind: "hologram", Tool: "claude-code"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if lm.lastFreshSpec.Tool != "" || lm.lastGUISpec.ID != "" {
		t.Errorf("an unknown kind reached a launch seam: fresh=%+v gui=%+v", lm.lastFreshSpec, lm.lastGUISpec)
	}
}

func TestGUILaunchSucceeds(t *testing.T) {
	id := anyAdvertisedGUIID(t)
	lm := &fakeLaunchManager{guiResult: GUILaunchResult{
		RunID: "RUN-1", PID: 777, ID: id, Label: "The IDE",
		WrapApplied: true, WrapNote: "cold-start only", Notes: []string{"a note"},
	}}
	s := newLaunchTestServer(t, lm)
	rec := postGUILaunch(t, s.Handler(), terminalLaunchRequest{Kind: "gui", Tool: id})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for key, want := range map[string]any{
		"kind":         "gui",
		"run_id":       "RUN-1",
		"pid":          float64(777),
		"tool":         id,
		"label":        "The IDE",
		"wrap_applied": true,
		"wrap_note":    "cold-start only",
	} {
		if out[key] != want {
			t.Errorf("%s = %v, want %v", key, out[key], want)
		}
	}
	if lm.lastGUISpec.ID != id {
		t.Errorf("gui spec = %+v, want id %s", lm.lastGUISpec, id)
	}
	// A GUI response must never carry a terminal token: there is no PTY to dock.
	if _, ok := out["token"]; ok {
		t.Errorf("gui response carried a token: %v", out)
	}
}

func TestGUILaunchRejectsUnknownID(t *testing.T) {
	lm := &fakeLaunchManager{}
	s := newLaunchTestServer(t, lm)
	rec := postGUILaunch(t, s.Handler(), terminalLaunchRequest{Kind: "gui", Tool: "not-a-gui-row"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if lm.lastGUISpec.ID != "" {
		t.Errorf("an unknown id reached the GUI seam: %+v", lm.lastGUISpec)
	}
}

// TestGUILaunchRefusesTerminalOnlyFields pins the fail-closed refusal: a caller
// that asked for a sandboxed, model-pinned launch must be told it cannot have
// one, never silently handed a bare IDE.
func TestGUILaunchRefusesTerminalOnlyFields(t *testing.T) {
	id := anyAdvertisedGUIID(t)
	tests := []struct {
		name string
		body terminalLaunchRequest
	}{
		{"sandbox", terminalLaunchRequest{Kind: "gui", Tool: id, Sandbox: true}},
		{"model", terminalLaunchRequest{Kind: "gui", Tool: id, Model: "opus"}},
		{"workspace_source", terminalLaunchRequest{Kind: "gui", Tool: id, WorkspaceSource: "clone-local"}},
		{"workspace_remote", terminalLaunchRequest{Kind: "gui", Tool: id, WorkspaceRemote: "git@x:y"}},
		{"workspace_branch", terminalLaunchRequest{Kind: "gui", Tool: id, WorkspaceBranch: "main"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lm := &fakeLaunchManager{}
			s := newLaunchTestServer(t, lm)
			rec := postGUILaunch(t, s.Handler(), tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
			}
			if lm.lastGUISpec.ID != "" {
				t.Errorf("a refused field still reached the GUI seam: %+v", lm.lastGUISpec)
			}
		})
	}
}

func TestGUILaunchMapsServiceErrors(t *testing.T) {
	id := anyAdvertisedGUIID(t)
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"fresh disabled", ErrLaunchFreshDisabled, http.StatusForbidden},
		{"tool not allowed", ErrLaunchToolNotAllowed, http.StatusForbidden},
		{"project root denied", ErrLaunchProjectRootDenied, http.StatusBadRequest},
		{"not launchable", ErrLaunchGUINotLaunchable, http.StatusBadRequest},
		{"gui seam absent", ErrLaunchGUIUnsupported, http.StatusNotImplemented},
		{"platform unsupported", ErrLaunchUnsupported, http.StatusNotImplemented},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newLaunchTestServer(t, &fakeLaunchManager{guiErr: tc.err})
			rec := postGUILaunch(t, s.Handler(), terminalLaunchRequest{Kind: "gui", Tool: id})
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// TestTerminalSessionsCarriesGUIKeys pins the ADDITIVE contract: the two new
// keys are present and every pre-existing key survives.
func TestTerminalSessionsCarriesGUIKeys(t *testing.T) {
	lm := &fakeLaunchManager{guiRunList: []GUIRunInfo{{
		RunID: "RUN-1", ID: "vscode", Label: "VS Code", PID: 42,
		LaunchedAt: time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC), WrapApplied: true,
		Notes: []string{"pid belongs to a launcher stub"},
	}}}
	s := newLaunchTestServer(t, lm)
	req := httptest.NewRequest(http.MethodGet, "/api/terminal/sessions", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, key := range []string{
		"sessions", "launchable_tools", "launchable_tool_info",
		"allowed_project_roots", "shell_enabled", "gui_launchables", "gui_runs",
	} {
		if _, ok := out[key]; !ok {
			t.Errorf("missing key %q", key)
		}
	}
	var runs []GUIRunInfo
	if err := json.Unmarshal(out["gui_runs"], &runs); err != nil {
		t.Fatalf("decode gui_runs: %v", err)
	}
	if len(runs) != 1 || runs[0].RunID != "RUN-1" || runs[0].PID != 42 {
		t.Errorf("gui_runs = %+v", runs)
	}
	// The mechanism notes (launcher-stub pid caveat) ride the run LIST, not
	// only the launch response, so a stub's exit never reads as the app's.
	if len(runs) == 1 && (len(runs[0].Notes) != 1 || runs[0].Notes[0] != "pid belongs to a launcher stub") {
		t.Errorf("gui_runs[0].notes = %q, want the seam's note on the wire", runs[0].Notes)
	}
	if !strings.Contains(string(out["gui_runs"]), `"notes":["pid belongs to a launcher stub"]`) {
		t.Errorf("gui_runs wire lacks the notes key: %s", out["gui_runs"])
	}
}

// TestGUILaunchableInfoShape pins the picker projection: advertised rows only,
// sorted by id, WrapNone rendered "none", and the two independent allow-lists.
func TestGUILaunchableInfoShape(t *testing.T) {
	t.Parallel()
	id := anyAdvertisedGUIID(t)
	cfg := config.Config{}
	cfg.Terminal.Launch.AllowedTools = []string{id}

	rows := guiLaunchableInfo(cfg)
	if len(rows) == 0 {
		t.Fatal("guiLaunchableInfo returned no rows for a registry with advertised rows")
	}
	var found *GUILaunchableInfo
	for i := range rows {
		if i > 0 && rows[i-1].ID > rows[i].ID {
			t.Errorf("rows are not sorted by id: %s before %s", rows[i-1].ID, rows[i].ID)
		}
		if rows[i].WrapKind == "" {
			t.Errorf("row %s carries an empty wrap_kind; WrapNone must render as \"none\"", rows[i].ID)
		}
		if !rows[i].Grounded {
			t.Errorf("row %s is advertised but not grounded", rows[i].ID)
		}
		if rows[i].ID == id {
			found = &rows[i]
		}
	}
	if found == nil {
		t.Fatalf("advertised row %s missing from the picker projection", id)
	}
	if !found.Allowed {
		t.Errorf("row %s: allowed = false, want true (it is in allowed_tools)", id)
	}
	for _, r := range rows {
		if r.ID != id && r.Allowed {
			t.Errorf("row %s: allowed = true, want false (not in allowed_tools)", r.ID)
		}
		// A pure editor HOST has no adapter to watch, so it must report watched
		// rather than inventing a capture gap.
		if r.Adapter == "" && !r.Watched {
			t.Errorf("host row %s: watched = false, want true (no adapter to watch)", r.ID)
		}
	}
}

// TestGUIRunsNilManagerIsEmptyArray pins the JSON contract: never a null.
func TestGUIRunsNilManagerIsEmptyArray(t *testing.T) {
	t.Parallel()
	s := &Server{}
	if got := s.guiRuns(); got == nil || len(got) != 0 {
		t.Errorf("guiRuns() = %v, want a non-nil empty slice", got)
	}
}

func TestWrapKindWire(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   integration.WrapKind
		want string
	}{
		{integration.WrapNone, "none"},
		{integration.WrapChildEnv, "child_env"},
		{integration.WrapConfigWrite, "config_write"},
	}
	for _, tc := range tests {
		if got := wrapKindWire(tc.in); got != tc.want {
			t.Errorf("wrapKindWire(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
