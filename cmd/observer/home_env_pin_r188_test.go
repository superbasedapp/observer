package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// R-188 F1 (plans ruling P-182): `HOME=/tmp/x observer init --claude-code`
// with CLAUDE_CONFIG_DIR exported wrote the hooks into the developer's real
// settings.json (cmd/observer handed hook.NewRegistry os.Getenv) while the
// proxy route went under /tmp/x (proxyroute applies the LEFT2 isolation
// rule). The one pinned-home rule (crossmount.HomeEnv) now decides for every
// writer, and the callers pass nil.
//
// The fixture is that shape inside temp dirs: HOME (and USERPROFILE) at a
// temp home, CLAUDE_CONFIG_DIR and CODEX_HOME at a second temp dir OUTSIDE
// it, and the account's real home staged at a third dir
// (ForeignLayoutForTest.RealHome), so crossmount.IsolationReason answers as
// it does for a real binary run under a scratch HOME (a test binary is
// otherwise never isolated). The init wiring (wireAIClients, production
// shape: no HomeDir) and the start wiring (autoRegisterHooks and the managed
// route maintenance pass) must write nothing at all under the second dir,
// and the hooks and the route must land together under the temp home. The
// control runs the init wiring unisolated: both the hooks and the route then
// follow the variables together, which shows the variables are live in
// these paths and the isolated cases are not vacuous. Not parallel: it sets
// HOME and stages process-wide crossmount state.
func TestR188IsolatedHomeKeepsHooksAndRouteUnderTheHome(t *testing.T) {
	requireComponents(t, "integration.hooks", "integration.proxy-route")
	requireActiveAdapters(t, "claude-code", "codex")
	requireAdapter(t, "claude-code")

	type fixture struct {
		home, outside       string
		claudeDir, codexDir string
	}
	setup := func(t *testing.T, isolate bool) fixture {
		t.Helper()
		f := fixture{home: filepath.Join(t.TempDir(), "home"), outside: filepath.Join(t.TempDir(), "outside")}
		f.claudeDir = filepath.Join(f.outside, "claude")
		f.codexDir = filepath.Join(f.outside, "codex")
		for _, d := range []string{filepath.Join(f.home, ".claude"), filepath.Join(f.home, ".codex"), f.claudeDir, f.codexDir} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		for _, p := range []string{filepath.Join(f.home, ".codex", "config.toml"), filepath.Join(f.codexDir, "config.toml")} {
			if err := os.WriteFile(p, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(f.claudeDir, "settings.json"), []byte("{\"sentinel\":\"developer-owned\"}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		// Every profile root and tool home in the temp home, then the two
		// relocation variables the audit names pointed outside it.
		pinToolHomesAt(t, f.home)
		t.Setenv("CLAUDE_CONFIG_DIR", f.claudeDir)
		t.Setenv("CODEX_HOME", f.codexDir)
		if isolate {
			r188Isolate(t)
		}
		return f
	}

	t.Run("init: nothing is written outside the isolated home", func(t *testing.T) {
		f := setup(t, true)
		before := r188Tree(t, f.outside)
		lines, _, _, _, err := wireAIClients(WireAIClientsOptions{
			ProxyPort: 18820, OnlyClaudeCode: true, OnlyCodex: true, SkipExtension: true,
		})
		if err != nil {
			t.Fatalf("wireAIClients: %v", err)
		}
		r188AssertUntouched(t, f.outside, before, strings.Join(lines, "\n"))
		r188AssertHooksAndRouteUnder(t, filepath.Join(f.home, ".claude"), filepath.Join(f.home, ".codex"), true, strings.Join(lines, "\n"))
	})

	t.Run("start: nothing is written outside the isolated home", func(t *testing.T) {
		f := setup(t, true)
		before := r188Tree(t, f.outside)
		var stdout, stderr bytes.Buffer
		autoRegisterHooks(&stdout, &stderr, "", false)
		step := newRouteMaintenance(routeMaintenanceConfig(t, f.home), healthyProxy(t),
			fixedPosture(govern.RoutePostureMaintain), nil, &stdout, &stderr)
		if !step(context.Background(), true) {
			t.Fatalf("route maintenance wrote no route\nstdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
		}
		out := stdout.String() + "\n" + stderr.String()
		r188AssertUntouched(t, f.outside, before, out)
		r188AssertHooksAndRouteUnder(t, filepath.Join(f.home, ".claude"), filepath.Join(f.home, ".codex"), false, out)
	})

	// G1 (Wave 5 audit finding 1): the removal and the settings editor sit
	// on the same rule. Observer's own wiring is planted in BOTH places
	// first (unisolated, init follows the variables outside; isolated, it
	// lands under HOME), so an uninstall that followed the variables would
	// have something outside to remove.
	t.Run("uninstall: nothing is removed outside the isolated home", func(t *testing.T) {
		f := setup(t, false)
		r188Wire(t)
		r188Isolate(t)
		r188Wire(t)
		before := r188Tree(t, f.outside)
		out := r188Uninstall(t)
		r188AssertUntouched(t, f.outside, before, out)
		r188AssertUnwired(t, filepath.Join(f.home, ".claude"), filepath.Join(f.home, ".codex"), out)
	})

	t.Run("control: unisolated, the uninstall follows the variables", func(t *testing.T) {
		f := setup(t, false)
		r188Wire(t)
		out := r188Uninstall(t)
		r188AssertUnwired(t, f.claudeDir, f.codexDir, out)
	})

	// The settings editor resolves every file through the relocation rules
	// (FU-140: agentconfigsvc.Service.env sets PathEnv.Relocate), so
	// CLAUDE_CONFIG_DIR and CODEX_HOME reach its save path and the isolated
	// Claude Code and Codex saves below bite: a save that read either
	// variable would land outside. The getenv it holds also expands the path
	// tokens ($XDG_CONFIG_HOME on Linux, %APPDATA% on Windows); that
	// variable is pointed outside too, and vtcode's user file (a path under
	// that token) is saved beside them. The controls below show each
	// variable is live in this path.
	t.Run("agent-config: a settings save writes nothing outside the isolated home", func(t *testing.T) {
		f := setup(t, false)
		xdg := r188PointConfigBaseOutside(t, f.outside)
		r188Isolate(t)
		before := r188Tree(t, f.outside)
		out := r188AgentConfigSet(t, f.home, "claude-code", "model", `"opus"`)
		r188AssertSaved(t, filepath.Join(f.home, ".claude", "settings.json"), `"opus"`, out)
		out += r188AgentConfigSet(t, f.home, "codex", "model", `model = "opus"`)
		r188AssertSaved(t, filepath.Join(f.home, ".codex", "config.toml"), `model = "opus"`, out)
		if xdg != "" {
			out += r188AgentConfigSet(t, f.home, "vtcode", "mcp.enabled", "enabled = true", "--file", "vtcode/user-config")
			r188AssertSaved(t, r188VTCodeUserConfig(r188DefaultConfigBase(f.home)), "enabled = true", out)
		}
		r188AssertUntouched(t, f.outside, before, out)
	})

	t.Run("control: unisolated, a settings save follows the relocation variables", func(t *testing.T) {
		f := setup(t, false)
		home := filepath.Join(f.home, ".claude")
		codexHome := filepath.Join(f.home, ".codex")
		beforeClaude, beforeCodex := r188Tree(t, home), r188Tree(t, codexHome)
		out := r188AgentConfigSet(t, f.home, "claude-code", "model", `"opus"`)
		r188AssertSaved(t, filepath.Join(f.claudeDir, "settings.json"), `"opus"`, out)
		out += r188AgentConfigSet(t, f.home, "codex", "model", `model = "opus"`)
		r188AssertSaved(t, filepath.Join(f.codexDir, "config.toml"), `model = "opus"`, out)
		r188AssertUntouched(t, home, beforeClaude, out)
		r188AssertUntouched(t, codexHome, beforeCodex, out)
	})

	t.Run("control: unisolated, a settings save follows the path variable", func(t *testing.T) {
		f := setup(t, false)
		xdg := r188PointConfigBaseOutside(t, f.outside)
		if xdg == "" {
			t.Skipf("no catalogued user settings path expands an environment variable on %s", runtime.GOOS)
		}
		out := r188AgentConfigSet(t, f.home, "vtcode", "mcp.enabled", "enabled = true", "--file", "vtcode/user-config")
		r188AssertSaved(t, r188VTCodeUserConfig(xdg), "enabled = true", out)
	})

	t.Run("control: unisolated, the hooks and the route follow the variables together", func(t *testing.T) {
		f := setup(t, false)
		lines, _, _, _, err := wireAIClients(WireAIClientsOptions{
			ProxyPort: 18820, OnlyClaudeCode: true, OnlyCodex: true, SkipExtension: true,
		})
		if err != nil {
			t.Fatalf("wireAIClients: %v", err)
		}
		r188AssertHooksAndRouteUnder(t, f.claudeDir, f.codexDir, true, strings.Join(lines, "\n"))
	})
}

// r188Isolate stages the account's real home at a temp dir so
// crossmount.IsolationReason answers as for a real binary run under a
// scratch HOME.
func r188Isolate(t *testing.T) {
	t.Helper()
	crossmount.StageForeignLayoutForTest(t, crossmount.ForeignLayoutForTest{
		Root: t.TempDir(), RealHome: t.TempDir(),
	})
	if crossmount.IsolationReason() == "" {
		t.Fatal("the staged real home did not isolate HOME; the test would prove nothing")
	}
}

// r188Wire runs the init wiring (production shape: no HomeDir) for Claude
// Code and Codex on the default proxy port, the one `observer uninstall`
// counts as this install's.
func r188Wire(t *testing.T) {
	t.Helper()
	lines, _, _, _, err := wireAIClients(WireAIClientsOptions{
		ProxyPort: 8820, OnlyClaudeCode: true, OnlyCodex: true, SkipExtension: true,
	})
	if err != nil {
		t.Fatalf("wireAIClients: %v\n%s", err, strings.Join(lines, "\n"))
	}
}

// r188Uninstall runs `observer uninstall --claude-code --codex`, which
// removes through clientwire.NewRemover (hooks, MCP, route, telemetry).
func r188Uninstall(t *testing.T) string {
	t.Helper()
	cmd := newUninstallCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--claude-code", "--codex"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("observer uninstall: %v\n%s", err, out.String())
	}
	return out.String()
}

// r188AgentConfigSet runs `observer agent-config set <tool> <setting>
// <value> [flags]`, the CLI shape of the settings editor (openAgentConfig
// builds the agentconfigsvc.Service with no Home and no Getenv, as the
// dashboard does), and checks it saved. want is the value as it reads in
// the written file.
func r188AgentConfigSet(t *testing.T, home, tool, setting, want string, flags ...string) string {
	t.Helper()
	cfgPath := filepath.Join(home, "observer-config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(filepath.Join(home, "none.db"))+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	value := "opus"
	if setting == "mcp.enabled" {
		value = "true"
	}
	cmd := newAgentConfigCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(append([]string{"set", tool, setting, value, "--config", cfgPath}, flags...))
	if err := cmd.Execute(); err != nil || !strings.Contains(out.String(), "saved") || !strings.Contains(out.String(), want) {
		t.Fatalf("observer agent-config set %s %s: %v\n%s", tool, setting, err, out.String())
	}
	return out.String()
}

// r188AssertSaved checks the settings save landed in path.
func r188AssertSaved(t *testing.T, path, want, out string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(b), want) {
		t.Errorf("the settings save did not land in %s (%v):\n%s\noutput:\n%s", path, err, b, out)
	}
}

// r188ConfigBaseVar is the variable that expands the base of vtcode's user
// settings path on this OS ("" where the path takes no variable).
func r188ConfigBaseVar() string {
	switch runtime.GOOS {
	case "linux":
		return "XDG_CONFIG_HOME"
	case "windows":
		return "APPDATA"
	}
	return ""
}

// r188PointConfigBaseOutside points r188ConfigBaseVar at a directory under
// outside and returns it ("" when this OS has no such variable).
func r188PointConfigBaseOutside(t *testing.T, outside string) string {
	t.Helper()
	name := r188ConfigBaseVar()
	if name == "" {
		return ""
	}
	dir := filepath.Join(outside, "config-base")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(name, dir)
	return dir
}

// r188DefaultConfigBase is what the path token expands to under home when
// no variable is read.
func r188DefaultConfigBase(home string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(home, "AppData", "Roaming")
	}
	return filepath.Join(home, ".config")
}

// r188VTCodeUserConfig is the vtcode/user-config row's path under base.
func r188VTCodeUserConfig(base string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(base, "vinhnx", "vtcode", "config", "vtcode.toml")
	}
	return filepath.Join(base, "vtcode", "vtcode.toml")
}

// r188AssertUnwired checks the uninstall removed Observer's Claude Code
// hooks and route from claudeDir/settings.json and the Codex route from
// codexDir/config.toml, so the removal ran where the test expects it.
func r188AssertUnwired(t *testing.T, claudeDir, codexDir, out string) {
	t.Helper()
	bin, err := absoluteBinaryPath()
	if err != nil {
		t.Fatal(err)
	}
	settings, err := os.ReadFile(filepath.Join(claudeDir, "settings.json"))
	if err != nil {
		t.Fatalf("read %s: %v\noutput:\n%s", claudeDir, err, out)
	}
	for _, gone := range []string{"ANTHROPIC_BASE_URL", filepath.ToSlash(bin), bin} {
		if strings.Contains(string(settings), gone) {
			t.Errorf("%s/settings.json still holds %q after the uninstall\n%s\noutput:\n%s", claudeDir, gone, settings, out)
		}
	}
	if cfg, err := os.ReadFile(filepath.Join(codexDir, "config.toml")); err != nil || strings.Contains(string(cfg), "openai-observer") {
		t.Errorf("codex route still in %s (%v):\n%s\noutput:\n%s", codexDir, err, cfg, out)
	}
}

// r188AssertHooksAndRouteUnder checks the Claude Code hooks and route sit
// in claudeDir/settings.json and the Codex hooks in codexDir/hooks.json,
// plus (codexRoute) the Codex route in codexDir/config.toml.
func r188AssertHooksAndRouteUnder(t *testing.T, claudeDir, codexDir string, codexRoute bool, out string) {
	t.Helper()
	settings, err := os.ReadFile(filepath.Join(claudeDir, "settings.json"))
	if err != nil {
		t.Fatalf("read %s: %v\noutput:\n%s", claudeDir, err, out)
	}
	for _, want := range []string{`"hooks"`, "ANTHROPIC_BASE_URL"} {
		if !strings.Contains(string(settings), want) {
			t.Errorf("%s/settings.json lacks %s: the hooks and the route did not land together\n%s\noutput:\n%s", claudeDir, want, settings, out)
		}
	}
	if _, err := os.Stat(filepath.Join(codexDir, "hooks.json")); err != nil {
		t.Errorf("codex hooks not under %s: %v\noutput:\n%s", codexDir, err, out)
	}
	if codexRoute {
		cfg, err := os.ReadFile(filepath.Join(codexDir, "config.toml"))
		if err != nil || !strings.Contains(string(cfg), "openai-observer") {
			t.Errorf("codex route not under %s (%v):\n%s\noutput:\n%s", codexDir, err, cfg, out)
		}
	}
}

// r188AssertUntouched fails on any file created, changed or removed under
// root since before.
func r188AssertUntouched(t *testing.T, root string, before map[string]string, out string) {
	t.Helper()
	after := r188Tree(t, root)
	for p, sum := range after {
		if b, ok := before[p]; !ok {
			t.Errorf("wrote %s outside the isolated home", filepath.Join(root, p))
		} else if b != sum {
			t.Errorf("changed %s outside the isolated home", filepath.Join(root, p))
		}
	}
	for p := range before {
		if _, ok := after[p]; !ok {
			t.Errorf("removed %s outside the isolated home", filepath.Join(root, p))
		}
	}
	if t.Failed() {
		t.Logf("output:\n%s", out)
	}
}

// r188Tree maps every entry under root (relative path) to its content
// digest; a directory maps to "dir".
func r188Tree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() {
			out[rel] = "dir"
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		out[rel] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}
