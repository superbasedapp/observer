package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// terminal_wire_gap_test.go covers the dashboard-install remediation wire shape
// (audit 2026-09-02, T6): JSON error bodies on the terminal routes (DI-05), the
// two-cause 503 copy (DI-16), the picker annotations (DI-06), the policy
// cross-check keys (DI-07), install_note passthrough (DI-03), the plain-shell
// preflight message (DI-18) and the deliberate un-gating of guided install
// (DI-21).

// newTerminalWireServer builds a loopback dashboard whose config file the test
// authors verbatim, so the two independent allow-lists
// ([terminal.launch].allowed_tools and [observer.watch].enabled_adapters) can be
// set to any combination — including the nil-vs-empty cases.
func newTerminalWireServer(t *testing.T, cfgBody string, lm LaunchManager, allowInstall func() bool, hint func(string) ([]string, string, bool)) http.Handler {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	database, err := openTestDB(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	cfgPath := filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = \"" + filepath.ToSlash(dbPath) + "\"\n" + cfgBody
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	rc, _ := newReadyRemoteController(t)
	s, err := New(Options{
		DB:               database,
		ConfigPath:       cfgPath,
		Remote:           rc,
		LaunchManager:    lm,
		AllowToolInstall: allowInstall,
		ToolInstallHint:  hint,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s.Handler()
}

// decodeErrBody asserts an application/json {"error": …} body and returns the
// error string.
func decodeErrBody(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json: %s", ct, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("body is not JSON (%v): %s", err, rec.Body.String())
	}
	msg, ok := out["error"].(string)
	if !ok {
		t.Fatalf("body has no string \"error\" key: %s", rec.Body.String())
	}
	return msg
}

// TestTerminalInstallErrorsAreJSON pins DI-05: EVERY non-200 on
// /api/terminal/install is application/json {"error": …}, so the SPA maps a
// status to copy instead of showing the raw body.
func TestTerminalInstallErrorsAreJSON(t *testing.T) {
	cases := []struct {
		name         string
		lm           LaunchManager
		allowInstall func() bool
		tool         string
		wantStatus   int
		wantContains string
	}{
		{
			name:         "503_no_launch_manager",
			lm:           nil,
			allowInstall: func() bool { return true },
			tool:         "codex",
			wantStatus:   http.StatusServiceUnavailable,
			wantContains: "allow_dashboard_launch",
		},
		{
			name:         "403_install_disabled",
			lm:           &fakeLaunchManager{},
			allowInstall: func() bool { return false },
			tool:         "codex",
			wantStatus:   http.StatusForbidden,
			wantContains: "[terminal.launch].allow_install",
		},
		{
			name:         "400_no_grounded_hint",
			lm:           &fakeLaunchManager{},
			allowInstall: func() bool { return true },
			tool:         "pi", // codexHint reports ok=false for anything but codex
			wantStatus:   http.StatusBadRequest,
			wantContains: "no grounded install command",
		},
		{
			name:         "400_missing_tool",
			lm:           &fakeLaunchManager{},
			allowInstall: func() bool { return true },
			tool:         "",
			wantStatus:   http.StatusBadRequest,
			wantContains: "missing tool",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newInstallServer(t, tc.lm, tc.allowInstall, codexHint)
			rec := postInstall(t, h, tc.tool)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if msg := decodeErrBody(t, rec); !strings.Contains(msg, tc.wantContains) {
				t.Errorf("error %q must contain %q", msg, tc.wantContains)
			}
		})
	}
}

// TestTerminalInstall503NamesBothCauses pins DI-16: a nil LaunchManager has
// exactly two causes and the copy names BOTH — never the stale pre-ConPTY
// "run the daemon under WSL/Linux" claim, which a native-Windows daemon
// disproves.
func TestTerminalInstall503NamesBothCauses(t *testing.T) {
	h := newInstallServer(t, nil, func() bool { return true }, codexHint)
	rec := postInstall(t, h, "codex")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", rec.Code, rec.Body.String())
	}
	msg := decodeErrBody(t, rec)
	for _, want := range []string{"[handoff].allow_dashboard_launch", "ConPTY", "1809"} {
		if !strings.Contains(msg, want) {
			t.Errorf("503 copy must name %q: %s", want, msg)
		}
	}
	if strings.Contains(msg, "WSL/Linux") {
		t.Errorf("503 copy must not repeat the stale pre-ConPTY WSL claim: %s", msg)
	}
}

// TestTerminalSessions503IsJSONWithBothCauses pins the same two-cause copy +
// JSON body on the VIEW route the picker polls (DI-05/DI-16) — the SPA showed
// "no launchable tools" because this 503 was a silently-swallowed plain-text
// body.
func TestTerminalSessions503IsJSONWithBothCauses(t *testing.T) {
	h := newTerminalWireServer(t, "", nil, func() bool { return true }, codexHint)
	req := httptest.NewRequest(http.MethodGet, "/api/terminal/sessions", nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", rec.Code, rec.Body.String())
	}
	msg := decodeErrBody(t, rec)
	if !strings.Contains(msg, "[handoff].allow_dashboard_launch") || !strings.Contains(msg, "ConPTY") {
		t.Errorf("sessions 503 must name both causes: %s", msg)
	}
}

// TestTerminalPreflightCarriesInstallNote pins DI-03: the honest-zero reason a
// tool has no guided install crosses the wire as install_note, and is OMITTED
// when empty (so a tool with a real install command carries no dead copy).
func TestTerminalPreflightCarriesInstallNote(t *testing.T) {
	const note = "no Windows build exists — see the vendor's docs"
	seam := func(tool string) (ToolPreflight, bool) {
		switch tool {
		case "muse":
			return ToolPreflight{Tool: tool, Verdict: "not_found", InstallNote: note}, true
		case "codex":
			return ToolPreflight{Tool: tool, Verdict: "not_found", InstallCommand: "npm install -g @openai/codex", CanInstall: true}, true
		}
		return ToolPreflight{}, false
	}
	s := newPreflightServer(t, seam)

	rec := getPreflight(t, s.Handler(), "muse")
	if rec.Code != http.StatusOK {
		t.Fatalf("preflight = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var got ToolPreflight
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.InstallNote != note {
		t.Errorf("install_note = %q, want %q", got.InstallNote, note)
	}
	if !strings.Contains(rec.Body.String(), `"install_note"`) {
		t.Errorf("wire must carry install_note: %s", rec.Body.String())
	}

	rec2 := getPreflight(t, s.Handler(), "codex")
	if strings.Contains(rec2.Body.String(), "install_note") {
		t.Errorf("install_note must be omitted when empty: %s", rec2.Body.String())
	}
}

// TestTerminalPreflightShellHasHonestMessage pins DI-18: the plain-shell
// pseudo-tool still 400s (there is no binary to resolve), but the copy says
// WHY instead of the misleading "not launchable" — the shell DOES launch.
func TestTerminalPreflightShellHasHonestMessage(t *testing.T) {
	seam := func(string) (ToolPreflight, bool) { return ToolPreflight{}, false }
	s := newPreflightServer(t, seam)
	rec := getPreflight(t, s.Handler(), termsvc.ShellTool)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("shell preflight = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "the plain shell has no binary to preflight") {
		t.Errorf("shell 400 copy = %q", body)
	}
	if strings.Contains(body, "not launchable") {
		t.Errorf("shell 400 must not claim the shell is not launchable: %q", body)
	}
}

// launchableToolInfoFromSessions GETs /api/terminal/sessions and returns the
// DI-06 annotations keyed by tool.
func launchableToolInfoFromSessions(t *testing.T, h http.Handler) map[string]LaunchableTool {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/terminal/sessions", nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/terminal/sessions = %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		LaunchableTools []string         `json:"launchable_tools"`
		Info            []LaunchableTool `json:"launchable_tool_info"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.LaunchableTools) == 0 {
		t.Fatal("launchable_tools must stay on the wire (existing clients decode it)")
	}
	if len(out.Info) != len(out.LaunchableTools) {
		t.Fatalf("launchable_tool_info has %d rows, launchable_tools has %d — the sibling key must cover the same set",
			len(out.Info), len(out.LaunchableTools))
	}
	byTool := make(map[string]LaunchableTool, len(out.Info))
	for _, row := range out.Info {
		byTool[row.Tool] = row
	}
	return byTool
}

// TestTerminalSessionsAnnotatesLaunchableTools pins DI-06: the picker's source
// route carries the LAUNCH gate (allowed_tools) and the CAPTURE gate
// (enabled_adapters) per tool, so the dialog stops learning them from a
// post-Start 403 / silent no-capture.
func TestTerminalSessionsAnnotatesLaunchableTools(t *testing.T) {
	cfg := "[terminal.launch]\nallowed_tools = [\"codex\"]\n\n[observer.watch]\nenabled_adapters = [\"claude-code\"]\n"
	h := newTerminalWireServer(t, cfg, &fakeLaunchManager{}, func() bool { return true }, codexHint)
	info := launchableToolInfoFromSessions(t, h)

	codex, ok := info["codex"]
	if !ok {
		t.Fatalf("codex missing from launchable_tool_info: %v", info)
	}
	if !codex.Allowed {
		t.Error("codex is in allowed_tools — allowed must be true")
	}
	if codex.Watched {
		t.Error("codex is NOT in enabled_adapters — watched must be false (the DI-07 gap)")
	}

	cc, ok := info["claude-code"]
	if !ok {
		t.Fatalf("claude-code missing from launchable_tool_info: %v", info)
	}
	if cc.Allowed {
		t.Error("claude-code is not in allowed_tools — allowed must be false")
	}
	if !cc.Watched {
		t.Error("claude-code is in enabled_adapters — watched must be true")
	}
}

// TestLaunchableToolInfoNilEnabledAdaptersMeansAllWatched pins the nil-vs-empty
// rule the annotation shares with adapter.Registry.Detected: an ABSENT
// enabled_adapters key watches everything, while an explicit empty list watches
// nothing. Exercised on the pure helper so the two cases are unambiguous (a
// loaded config always carries the non-nil default list).
func TestLaunchableToolInfoNilEnabledAdaptersMeansAllWatched(t *testing.T) {
	var nilCfg config.Config // EnabledAdapters == nil
	for _, row := range launchableToolInfo(nilCfg) {
		if !row.Watched {
			t.Fatalf("nil enabled_adapters must mark every tool watched; %s was not", row.Tool)
		}
		if row.Allowed {
			t.Fatalf("no allowed_tools must mark every tool not-allowed; %s was allowed", row.Tool)
		}
	}

	var emptyCfg config.Config
	emptyCfg.Observer.Watch.EnabledAdapters = []string{} // explicit "watch nothing"
	for _, row := range launchableToolInfo(emptyCfg) {
		if row.Watched {
			t.Fatalf("explicit empty enabled_adapters must watch nothing; %s was watched", row.Tool)
		}
	}
}

// TestTerminalPolicyReportsUnwatchedAllowedTools pins DI-07 on the policy GET:
// enabled_adapters is echoed as loaded, and the server derives the cross-check
// so the SPA never reimplements the nil-vs-empty rule.
func TestTerminalPolicyReportsUnwatchedAllowedTools(t *testing.T) {
	cfg := "[terminal.launch]\nallowed_tools = [\"muse\", \"codex\"]\n\n[observer.watch]\nenabled_adapters = [\"claude-code\", \"codex\"]\n"
	h := newTerminalWireServer(t, cfg, &fakeLaunchManager{}, func() bool { return true }, codexHint)

	req := httptest.NewRequest(http.MethodGet, "/api/terminal/policy", nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET policy = %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		AllowedTools          []string `json:"allowed_tools"`
		EnabledAdapters       []string `json:"enabled_adapters"`
		UnwatchedAllowedTools []string `json:"unwatched_allowed_tools"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if strings.Join(out.EnabledAdapters, ",") != "claude-code,codex" {
		t.Errorf("enabled_adapters = %v, want the list as loaded", out.EnabledAdapters)
	}
	if strings.Join(out.UnwatchedAllowedTools, ",") != "muse" {
		t.Errorf("unwatched_allowed_tools = %v, want [muse]", out.UnwatchedAllowedTools)
	}
	if strings.Join(out.AllowedTools, ",") != "muse,codex" {
		t.Errorf("allowed_tools = %v, want the policy unchanged", out.AllowedTools)
	}
}

// TestTerminalPolicyUnwatchedIsEmptyWhenEveryAllowedToolIsWatched pins the
// no-gap case: the key is always present (never null) so the SPA can render
// without a null check.
func TestTerminalPolicyUnwatchedIsEmptyWhenEveryAllowedToolIsWatched(t *testing.T) {
	cfg := "[terminal.launch]\nallowed_tools = [\"codex\"]\n\n[observer.watch]\nenabled_adapters = [\"codex\"]\n"
	h := newTerminalWireServer(t, cfg, &fakeLaunchManager{}, func() bool { return true }, codexHint)
	req := httptest.NewRequest(http.MethodGet, "/api/terminal/policy", nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET policy = %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	gap, ok := out["unwatched_allowed_tools"]
	if !ok {
		t.Fatal("unwatched_allowed_tools must always be present")
	}
	if rows, isSlice := gap.([]any); !isSlice || len(rows) != 0 {
		t.Errorf("unwatched_allowed_tools = %v, want []", gap)
	}
}

// TestTerminalInstallIsNotGatedByAllowedTools pins the DI-21 decision: guided
// install stays UNGATED by [terminal.launch].allowed_tools. Installing is not
// launching — an operator must not have to widen the launch allow-list merely
// to obtain a binary. With an explicitly EMPTY allow-list (deny every launch),
// installing codex still reaches the spawn seam with the registry argv.
func TestTerminalInstallIsNotGatedByAllowedTools(t *testing.T) {
	cfg := "[terminal.launch]\nallow_fresh_agent = false\nallowed_tools = []\n"
	lm := &fakeLaunchManager{}
	h := newTerminalWireServer(t, cfg, lm, func() bool { return true }, codexHint)
	rec := postInstall(t, h, "codex")
	if rec.Code != http.StatusOK {
		t.Fatalf("install with empty allowed_tools = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if strings.Join(lm.lastSetupSpec.Argv, "|") != strings.Join(codexArgv, "|") {
		t.Errorf("spawned argv = %v, want the registry constant %v", lm.lastSetupSpec.Argv, codexArgv)
	}
	if lm.lastSetupSpec.Label != "install:codex" {
		t.Errorf("setup label = %q, want install:codex", lm.lastSetupSpec.Label)
	}
}

// TestTerminalInstallJSONBodyRejectionIsJSON pins that even the decoder's own
// 400 (a malformed body) obeys DI-05.
func TestTerminalInstallJSONBodyRejectionIsJSON(t *testing.T) {
	h := newInstallServer(t, &fakeLaunchManager{}, func() bool { return true }, codexHint)
	ck, ctok := getConfirm(t, h)
	req := httptest.NewRequest(http.MethodPost, "/api/terminal/install", bytes.NewReader([]byte("{not json")))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(ck)
	req.Header.Set(remoteConfirmHeader, ctok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed body = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if msg := decodeErrBody(t, rec); !strings.Contains(msg, "invalid JSON body") {
		t.Errorf("error = %q, want the invalid-JSON reason", msg)
	}
}
