package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

func putSandboxConfig(t *testing.T, h http.Handler, body string) (int, map[string]any) {
	t.Helper()
	greq := httptest.NewRequest(http.MethodGet, "/api/terminal/sandbox/config", nil)
	greq.Host = "127.0.0.1:8080"
	grec := httptest.NewRecorder()
	h.ServeHTTP(grec, greq)
	if grec.Code != http.StatusOK {
		t.Fatalf("GET sandbox config = %d: %s", grec.Code, grec.Body.String())
	}
	var get struct {
		ConfirmToken string `json:"confirm_token"`
	}
	if err := json.Unmarshal(grec.Body.Bytes(), &get); err != nil {
		t.Fatalf("decode sandbox config GET: %v", err)
	}
	var confirmCookie *http.Cookie
	for _, c := range grec.Result().Cookies() {
		if c.Name == remoteConfirmCookie {
			confirmCookie = c
		}
	}
	if get.ConfirmToken == "" || confirmCookie == nil {
		t.Fatal("sandbox config GET did not mint confirm token + cookie")
	}

	req := httptest.NewRequest(http.MethodPut, "/api/terminal/sandbox/config", strings.NewReader(body))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(remoteConfirmHeader, get.ConfirmToken)
	req.AddCookie(confirmCookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestTerminalSandboxConfigGetDefaults(t *testing.T) {
	_, h := newManageServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/terminal/sandbox/config", nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		ConfirmToken          string                       `json:"confirm_token"`
		ConfigWritable        bool                         `json:"config_writable"`
		RestartRequiredOnSave bool                         `json:"restart_required_on_save"`
		Sandbox               terminalSandboxConfigPayload `json:"sandbox"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ConfirmToken == "" || !got.ConfigWritable || !got.RestartRequiredOnSave {
		t.Fatalf("honesty fields missing: %+v", got)
	}
	if got.Sandbox.Enabled || got.Sandbox.Backend != "bwrap" || got.Sandbox.HomeMode != "tmpfs" || got.Sandbox.PrepTimeoutSeconds != 300 {
		t.Fatalf("sandbox defaults = %+v", got.Sandbox)
	}
	if got.Sandbox.RemoteAllowedHosts == nil || got.Sandbox.MaskPaths == nil || got.Sandbox.ExtraROBinds == nil || got.Sandbox.ExtraRWBinds == nil {
		t.Fatalf("list defaults must serialize as [] rather than null: %+v", got.Sandbox)
	}
}

func TestTerminalSandboxConfigPutRoundTripPreservesLaunchPolicy(t *testing.T) {
	s, h := newManageServer(t)
	root := t.TempDir()
	body := `{
		"enabled":true,
		"backend":"bwrap",
		"home_mode":"readonly",
		"default_on":true,
		"allow_remote_clone":true,
		"remote_allowed_hosts":["github.com"," github.com ","gitlab.com"],
		"allow_worktree_source":true,
		"workspaces_dir":"` + filepath.ToSlash(filepath.Join(root, "sandboxes")) + `",
		"workspace_retention_days":7,
		"mask_paths":["/mnt/c"," /mnt/c "],
		"extra_ro_binds":["/opt/shared"],
		"extra_rw_binds":["/tmp/cache"],
		"prep_timeout_seconds":90
	}`
	code, out := putSandboxConfig(t, h, body)
	if code != http.StatusOK {
		t.Fatalf("PUT = %d: %v", code, out)
	}
	if out["saved"] != true || out["restart_required"] != true {
		t.Fatalf("save honesty fields = %v", out)
	}

	cfg, err := config.Load(config.LoadOptions{GlobalPath: s.opts.ConfigPath})
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.Terminal.Sandbox
	if !got.Enabled || !got.DefaultOn || !got.AllowRemoteClone || !got.AllowWorktreeSource || got.HomeMode != "readonly" {
		t.Fatalf("persisted sandbox flags = %+v", got)
	}
	if len(got.RemoteAllowedHosts) != 2 || len(got.MaskPaths) != 1 || len(got.ExtraROBinds) != 1 || len(got.ExtraRWBinds) != 1 {
		t.Fatalf("lists were not trimmed/deduped: %+v", got)
	}
	// A sandbox-only write must not silently authorize fresh agents or shells.
	if cfg.Terminal.Launch.AllowFreshAgent || cfg.Terminal.Launch.AllowShell || len(cfg.Terminal.Launch.AllowedTools) != 0 {
		t.Fatalf("sandbox PUT clobbered launch policy: %+v", cfg.Terminal.Launch)
	}
}

func TestTerminalSandboxConfigPutRejectsInvalidValues(t *testing.T) {
	_, h := newManageServer(t)
	tests := []struct {
		name string
		body string
	}{
		{"unknown home mode", `{"backend":"bwrap","home_mode":"writable","prep_timeout_seconds":300}`},
		{"negative retention", `{"backend":"bwrap","home_mode":"tmpfs","workspace_retention_days":-1,"prep_timeout_seconds":300}`},
		{"relative workspaces dir", `{"backend":"bwrap","home_mode":"tmpfs","workspaces_dir":"relative","prep_timeout_seconds":300}`},
		{"relative rw bind", `{"backend":"bwrap","home_mode":"tmpfs","extra_rw_binds":["relative"],"prep_timeout_seconds":300}`},
		{"unknown egress tier", `{"backend":"bwrap","home_mode":"tmpfs","egress":"wide-open","prep_timeout_seconds":300}`},
		{"public egress allow cidr", `{"backend":"bwrap","home_mode":"tmpfs","egress_allow_cidrs":["8.8.8.0/24"],"prep_timeout_seconds":300}`},
		{"loopback egress allow cidr", `{"backend":"bwrap","home_mode":"tmpfs","egress_allow_cidrs":["127.0.0.0/8"],"prep_timeout_seconds":300}`},
		{"non-cidr egress allow entry", `{"backend":"bwrap","home_mode":"tmpfs","egress_allow_cidrs":["registry.corp"],"prep_timeout_seconds":300}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, _ := putSandboxConfig(t, h, tc.body)
			if code != http.StatusBadRequest {
				t.Fatalf("PUT = %d, want 400 validation failure", code)
			}
		})
	}
}

func TestTerminalSandboxConfigPutRequiresConfirmation(t *testing.T) {
	_, h := newManageServer(t)
	req := httptest.NewRequest(http.MethodPut, "/api/terminal/sandbox/config", strings.NewReader(`{"backend":"bwrap","home_mode":"tmpfs"}`))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unconfirmed PUT = %d, want 403", rec.Code)
	}
}

// TestTerminalSandboxConfigEgressRoundTrip pins the SR27-SBX-1 knobs: the GET
// reports the effective tier ("internet" for the default), an explicit PUT
// persists both knobs, and a PUT from a client that predates them (fields
// omitted) KEEPS the saved values instead of resetting them.
func TestTerminalSandboxConfigEgressRoundTrip(t *testing.T) {
	s, h := newManageServer(t)
	load := func() config.TerminalSandboxConfig {
		t.Helper()
		cfg, err := config.Load(config.LoadOptions{GlobalPath: s.opts.ConfigPath})
		if err != nil {
			t.Fatal(err)
		}
		return cfg.Terminal.Sandbox
	}

	code, out := putSandboxConfig(t, h, `{"backend":"bwrap","home_mode":"tmpfs","prep_timeout_seconds":300,"egress":"proxy_only","allow_tool_config_writes":true}`)
	if code != http.StatusOK {
		t.Fatalf("PUT = %d: %v", code, out)
	}
	if got := load(); got.Egress != "proxy_only" || !got.AllowToolConfigWrites {
		t.Fatalf("explicit PUT persisted %+v", got)
	}
	sb, _ := out["sandbox"].(map[string]any)
	if sb["egress"] != "proxy_only" || sb["allow_tool_config_writes"] != true {
		t.Fatalf("PUT response sandbox = %v", sb)
	}

	code, out = putSandboxConfig(t, h, `{"enabled":true,"backend":"bwrap","home_mode":"tmpfs","prep_timeout_seconds":300}`)
	if code != http.StatusOK {
		t.Fatalf("legacy PUT = %d: %v", code, out)
	}
	if got := load(); got.Egress != "proxy_only" || !got.AllowToolConfigWrites || !got.Enabled {
		t.Fatalf("a PUT omitting the new fields reset them: %+v", got)
	}
}

// TestTerminalSandboxConfigEgressAllowCIDRsRoundTrip pins the private
// destination allow-list: an explicit PUT persists it (trimmed, deduped),
// the GET reports it, and a PUT that omits the field keeps it.
func TestTerminalSandboxConfigEgressAllowCIDRsRoundTrip(t *testing.T) {
	s, h := newManageServer(t)
	load := func() config.TerminalSandboxConfig {
		t.Helper()
		cfg, err := config.Load(config.LoadOptions{GlobalPath: s.opts.ConfigPath})
		if err != nil {
			t.Fatal(err)
		}
		return cfg.Terminal.Sandbox
	}
	code, out := putSandboxConfig(t, h, `{"backend":"bwrap","home_mode":"tmpfs","prep_timeout_seconds":300,"egress_allow_cidrs":[" 10.20.0.0/16 ","10.20.0.0/16","fd00:1::/32",""]}`)
	if code != http.StatusOK {
		t.Fatalf("PUT = %d: %v", code, out)
	}
	if got := load().EgressAllowCIDRs; len(got) != 2 || got[0] != "10.20.0.0/16" || got[1] != "fd00:1::/32" {
		t.Fatalf("persisted egress_allow_cidrs = %v", got)
	}
	code, out = putSandboxConfig(t, h, `{"enabled":true,"backend":"bwrap","home_mode":"tmpfs","prep_timeout_seconds":300}`)
	if code != http.StatusOK {
		t.Fatalf("legacy PUT = %d: %v", code, out)
	}
	if got := load().EgressAllowCIDRs; len(got) != 2 {
		t.Fatalf("a PUT omitting egress_allow_cidrs reset it: %v", got)
	}
	sb, _ := out["sandbox"].(map[string]any)
	if list, _ := sb["egress_allow_cidrs"].([]any); len(list) != 2 {
		t.Fatalf("response egress_allow_cidrs = %v", sb["egress_allow_cidrs"])
	}
	code, _ = putSandboxConfig(t, h, `{"backend":"bwrap","home_mode":"tmpfs","prep_timeout_seconds":300,"egress_allow_cidrs":[]}`)
	if code != http.StatusOK {
		t.Fatalf("clearing PUT = %d", code)
	}
	if got := load().EgressAllowCIDRs; len(got) != 0 {
		t.Fatalf("an explicit empty list did not clear: %v", got)
	}
}
