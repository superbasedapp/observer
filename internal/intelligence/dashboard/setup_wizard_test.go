package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/hook"
)

// wizardTestServer sandboxes setupWizardHome into a temp dir so the
// write endpoints can never touch the developer's real tool configs.
func wizardTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	tdir := t.TempDir()
	home := filepath.Join(tdir, "home")
	for _, d := range []string{".claude", ".cursor", ".codex"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	prev := setupWizardHome
	setupWizardHome = home
	t.Cleanup(func() { setupWizardHome = prev })

	cfgPath := filepath.Join(tdir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\nlog_level = \"warn\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	return server, home
}

func wizardPost(t *testing.T, s *Server, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr,
		httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
	return rr
}

// TestSetupHooksWizard pins the dry-run → write → idempotent-recheck
// cycle for the hooks endpoint, sandboxed away from the real home.
func TestSetupHooksWizard(t *testing.T) {
	server, home := wizardTestServer(t)

	// Dry run: would add events, writes nothing.
	rr := wizardPost(t, server, "/api/setup/hooks",
		`{"tool":"claude-code","dry_run":true}`)
	if rr.Code != 200 {
		t.Fatalf("dry run: %d body=%s", rr.Code, rr.Body.String())
	}
	var dry struct {
		HooksAdded []string `json:"hooks_added"`
		DryRun     bool     `json:"dry_run"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&dry); err != nil {
		t.Fatal(err)
	}
	if !dry.DryRun || len(dry.HooksAdded) == 0 {
		t.Fatalf("dry run shape: %+v", dry)
	}
	settings := filepath.Join(home, ".claude", "settings.json")
	if _, err := os.Stat(settings); err == nil {
		t.Fatal("dry run wrote settings.json")
	}

	// Real write lands the hook entries.
	rr = wizardPost(t, server, "/api/setup/hooks", `{"tool":"claude-code"}`)
	if rr.Code != 200 {
		t.Fatalf("write: %d body=%s", rr.Code, rr.Body.String())
	}
	body, err := os.ReadFile(settings)
	if err != nil {
		t.Fatalf("settings.json not written: %v", err)
	}
	if !strings.Contains(string(body), "hook claude-code") {
		t.Errorf("settings.json missing observer hook command:\n%s", body)
	}

	// Second write reports already-set (idempotent, byte-equivalent
	// to a re-run of `observer init`).
	rr = wizardPost(t, server, "/api/setup/hooks", `{"tool":"claude-code"}`)
	if rr.Code != 200 {
		t.Fatalf("rewrite: %d body=%s", rr.Code, rr.Body.String())
	}
	var again struct {
		HooksAdded []string `json:"hooks_added"`
		AlreadySet []string `json:"already_set"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&again); err != nil {
		t.Fatal(err)
	}
	if len(again.HooksAdded) != 0 || len(again.AlreadySet) == 0 {
		t.Errorf("idempotency: added=%v already=%v", again.HooksAdded, again.AlreadySet)
	}
}

// TestSetupMCPWizard pins the MCP step's write + idempotency + the
// guard matrix shared with hooks.
func TestSetupMCPWizard(t *testing.T) {
	server, home := wizardTestServer(t)

	rr := wizardPost(t, server, "/api/setup/mcp", `{"tool":"claude-code"}`)
	if rr.Code != 200 {
		t.Fatalf("write: %d body=%s", rr.Code, rr.Body.String())
	}
	var got struct {
		Added      bool   `json:"added"`
		ConfigPath string `json:"config_path"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if !got.Added {
		t.Fatalf("first MCP write not added: %+v", got)
	}
	body, err := os.ReadFile(filepath.Join(home, ".claude.json"))
	if err != nil {
		t.Fatalf("mcp config not written: %v", err)
	}
	if !strings.Contains(string(body), `"observer"`) {
		t.Errorf("mcp entry missing:\n%s", body)
	}

	rr = wizardPost(t, server, "/api/setup/mcp", `{"tool":"claude-code"}`)
	var again struct {
		AlreadySet bool `json:"already_set"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&again); err != nil {
		t.Fatal(err)
	}
	if rr.Code != 200 || !again.AlreadySet {
		t.Errorf("idempotency: code=%d already=%v", rr.Code, again.AlreadySet)
	}

	// Guards: unknown tool 400, GET 405.
	if rr := wizardPost(t, server, "/api/setup/mcp", `{"tool":"nope"}`); rr.Code != 400 {
		t.Errorf("unknown tool: got %d want 400", rr.Code)
	}
	rr2 := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/api/setup/hooks", nil))
	if rr2.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET hooks: got %d want 405", rr2.Code)
	}
}

// TestSetupHooksWizardWindowsShellWarning: /api/setup/hooks carries the
// registration's non-fatal warnings. A Windows observer registering VT Code
// with no sh.exe on its PATH gets the hook-shell warning; with sh.exe on PATH
// the key is absent (additive shape).
func TestSetupHooksWizardWindowsShellWarning(t *testing.T) {
	noSh := t.TempDir()
	withSh := t.TempDir()
	if err := os.WriteFile(filepath.Join(withSh, "sh.exe"), []byte("stub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		path     string
		wantWarn bool
	}{
		{"sh missing", noSh, true},
		{"sh present", noSh + ";" + withSh, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := wizardTestServer(t)
			env := map[string]string{"PATH": tc.path}
			server.opts.HookRegistryOptions = func() (hook.Options, error) {
				return hook.Options{
					BinaryPath: "/opt/observer/bin/observer",
					GOOS:       "windows",
					Getenv:     func(k string) string { return env[k] },
				}, nil
			}
			rr := wizardPost(t, server, "/api/setup/hooks", `{"tool":"vtcode","dry_run":true}`)
			if rr.Code != 200 {
				t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
			}
			var got map[string]any
			if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			warnings, present := got["warnings"].([]any)
			if !tc.wantWarn {
				if present {
					t.Fatalf("unexpected warnings: %v", got["warnings"])
				}
				return
			}
			if len(warnings) != 1 || !strings.Contains(warnings[0].(string), "sh.exe is not on the Windows PATH") {
				t.Fatalf("warnings = %v (body %v)", got["warnings"], got)
			}
		})
	}
}
