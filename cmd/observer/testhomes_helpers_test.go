package main

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// testhomes_helpers_test.go is the ONE place cmd/observer tests pin every
// per-user home a config writer or reader can resolve (surface-gap FU-4 and
// FU-20). A test that sets only HOME still reaches the real profile on
// Windows (os.UserHomeDir reads USERPROFILE, and the registrars read APPDATA
// and LOCALAPPDATA directly), and a tool home variable set in the
// developer's own shell (CODEX_HOME, KIRO_HOME, ...) moves a writer off the
// test home altogether. On the 2026-10-25 Windows host that made the suite
// try to write the real %USERPROFILE%\.qwen\settings.json,
// %APPDATA%\devin\config.json and %USERPROFILE%\.prime\agent\models.json
// (refused by crossmount.CheckTestWrite) and read the real VT Code
// vtcode.toml.
//
// Two users:
//   - pinToolHomes / pinToolHomesAt: a test that drives a writer, a probe or
//     a detector pins all of them to its own temp home.
//   - pinProcessToolHomes: TestMain pins them for the whole run to one
//     process temp home first, so a test that forgets is still kept off the
//     real profile (it lands in a shared temp home instead, whose
//     ~/.observer is a file, so no default Observer database opens there).
//
// TestToolHomeVarsCoverTheWriters keeps the table honest: it scans the
// writers' and readers' sources for home-variable names and fails on one
// the table neither pins nor excludes with a reason.

// homeVarAction is what pinning does to one variable.
type homeVarAction int

const (
	// homeVarSet: set to a path under the temp home (rel; "" = the home).
	homeVarSet homeVarAction = iota
	// homeVarClear: unset, so every reader falls back to its default under
	// the (pinned) home. A tool home variable is cleared, never pointed at
	// some other directory, so a test's own expectations of "<home>/.tool"
	// hold.
	homeVarClear
)

// homeVar is one row of the pin table.
type homeVar struct {
	name   string
	action homeVarAction
	rel    []string // homeVarSet only: the path under the home
}

// toolHomeVars is the pin table: the profile variables first, then every
// tool home and config-relocation variable a writer, detector or the
// agentconfig relocation rules read. Order is the apply order.
var toolHomeVars = []homeVar{
	// Profile roots (POSIX, Windows).
	{name: "HOME", action: homeVarSet},
	{name: "USERPROFILE", action: homeVarSet},
	{name: "APPDATA", action: homeVarSet, rel: []string{"AppData", "Roaming"}},
	{name: "LOCALAPPDATA", action: homeVarSet, rel: []string{"AppData", "Local"}},
	// XDG base dirs: cleared, so they fall back under HOME (Linux, macOS)
	// and the Windows readers fall back to APPDATA / LOCALAPPDATA as they
	// would on a clean machine.
	{name: "XDG_CONFIG_HOME", action: homeVarClear},
	{name: "XDG_DATA_HOME", action: homeVarClear},
	{name: "XDG_STATE_HOME", action: homeVarClear},
	{name: "XDG_CACHE_HOME", action: homeVarClear},
	// Tool homes and config-file relocations.
	{name: "ANTHROPIC_CONFIG_DIR", action: homeVarClear},
	{name: "AUTOHAND_CONFIG", action: homeVarClear},
	{name: "AUTOHAND_HOME", action: homeVarClear},
	{name: "CLAUDE_CODE_DEBUG_LOGS_DIR", action: homeVarClear},
	{name: "CLAUDE_CODE_PLUGIN_CACHE_DIR", action: homeVarClear},
	{name: "CLAUDE_CODE_PLUGIN_SEED_DIR", action: homeVarClear},
	{name: "CLAUDE_CONFIG_DIR", action: homeVarClear},
	{name: "CLAUDE_HOME", action: homeVarClear},
	{name: "CLINE_DATA_DIR", action: homeVarClear},
	{name: "AIDER_DESK_DIR", action: homeVarClear},
	{name: "AIDER_DESK_HOME_DIR", action: homeVarClear},
	{name: "CLINE_DIR", action: homeVarClear},
	{name: "CLINE_GLOBAL_SETTINGS_PATH", action: homeVarClear},
	{name: "CLINE_MCP_SETTINGS_PATH", action: homeVarClear},
	{name: "CLINE_PROVIDER_SETTINGS_PATH", action: homeVarClear},
	{name: "CODEBUDDY_CONFIG_DIR", action: homeVarClear},
	{name: "CODEX_HOME", action: homeVarClear},
	{name: "CORTEX_HOME", action: homeVarClear},
	{name: "CRUSH_GLOBAL_CONFIG", action: homeVarClear},
	{name: "DEEPAGENTS_HOME", action: homeVarClear},
	{name: "VTCODE_HOME", action: homeVarClear},
	{name: "VTCODE_CONFIG", action: homeVarClear},
	{name: "DIMCODE_HOME", action: homeVarClear},
	{name: "DIRAC_DATA_DIR", action: homeVarClear},
	{name: "DIRAC_DIR", action: homeVarClear},
	{name: "HERMES_HOME", action: homeVarClear},
	{name: "INTERPRETER_HOME", action: homeVarClear},
	{name: "JUNIE_HOME", action: homeVarClear},
	{name: "KIMCHI_CODING_AGENT_DIR", action: homeVarClear},
	{name: "KIMI_CODE_HOME", action: homeVarClear},
	{name: "KIROCREW_HOME", action: homeVarClear},
	{name: "KIRO_HOME", action: homeVarClear},
	{name: "MISTRALCODE_GLOBAL_DIR", action: homeVarClear},
	{name: "PI_CODING_AGENT_DIR", action: homeVarClear},
	{name: "QWEN_HOME", action: homeVarClear},
	{name: "SNOWFLAKE_HOME", action: homeVarClear},
	{name: "VIBE_HOME", action: homeVarClear},
	// The Wave 4 per-tool home rules (lane w4-homes-b, relocate_homes.go).
	{name: "COPILOT_HOME", action: homeVarClear},
	{name: "COPILOT_PROVIDERS_CONFIG", action: homeVarClear},
	{name: "CRUSH_GLOBAL_DATA", action: homeVarClear},
	{name: "GEMINI_CLI_HOME", action: homeVarClear},
	{name: "GOOSE_PATH_ROOT", action: homeVarClear},
	{name: "GROK_HOME", action: homeVarClear},
	{name: "HERMES_DATA_DIR_SUFFIX", action: homeVarClear},
	{name: "KILO_CONFIG_DIR", action: homeVarClear},
	{name: "OPENCODE_CONFIG_DIR", action: homeVarClear},
	{name: "PRIME_AGENT_CODING_AGENT_DIR", action: homeVarClear},
	{name: "QODER_CONFIG_DIR", action: homeVarClear},
	// Observer's own per-user locations.
	{name: "OBSERVER_AGENT_RUNTIME_DIR", action: homeVarClear},
	{name: "OBSERVER_CONFIG", action: homeVarClear},
	{name: "OBSERVER_UPDATE_STATE_DIR", action: homeVarClear},
}

// notAToolHome lists the home-shaped variable names the source scan finds
// that the table deliberately leaves alone, each with the reason.
var notAToolHome = map[string]string{
	"XDG_RUNTIME_DIR":    "a runtime socket directory, not config; a temp path there can exceed the unix socket length limit",
	"GIT_DIR":            "a git repository variable read from a child process env, not a home",
	"GIT_COMMON_DIR":     "a git repository variable read from a child process env, not a home",
	"GIT_CONFIG":         "a git variable read from a child process env, not a home",
	"CLAUDE_PROJECT_DIR": "the project directory Claude Code hands its hooks, not a home",
	"COPILOT_HOOK_DIR":   "a host signal the Copilot CLI runtime sets on its hook processes; foreignhost.go reads only whether it is set, never the path",
	"CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR": "a boolean Claude Code knob, not a path",
	"CARGO_HOME":                "a toolchain install root read only to resolve binaries, never written",
	"BUN_INSTALL_CACHE_DIR":     "a package manager cache, read only to resolve binaries, never written",
	"OBSERVER_SANDBOX_SOCK_DIR": "set by the sandbox tests themselves for the helper socket",
	"OBSERVER_SANDBOX_BOX_DIR":  "set by the sandbox tests themselves for the sandbox box",
}

// toolHomeEnv resolves the pin table against home: name -> value, where ""
// means unset.
func toolHomeEnv(home string) map[string]string {
	out := make(map[string]string, len(toolHomeVars))
	for _, v := range toolHomeVars {
		switch v.action {
		case homeVarSet:
			out[v.name] = filepath.Join(append([]string{home}, v.rel...)...)
		case homeVarClear:
			out[v.name] = ""
		}
	}
	return out
}

// pinToolHomes pins every variable in toolHomeVars to a fresh t.TempDir()
// home and returns it. The previous values come back when the test ends.
// Not for parallel tests (it uses t.Setenv).
func pinToolHomes(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	pinToolHomesAt(t, home)
	return home
}

// pinToolHomesAt is pinToolHomes for a home the test already made. The
// directories are not created (a test that asserts nothing was written
// under the home keeps holding); every writer makes its own parents.
func pinToolHomesAt(t *testing.T, home string) {
	t.Helper()
	for _, g := range goToolchainVars {
		if os.Getenv(g.name) != "" {
			continue
		}
		if v := g.fallback(); v != "" {
			t.Setenv(g.name, v)
		}
	}
	env := toolHomeEnv(home)
	for _, v := range toolHomeVars {
		val := env[v.name]
		t.Setenv(v.name, val)
		if val == "" {
			if err := os.Unsetenv(v.name); err != nil {
				t.Fatalf("unset %s: %v", v.name, err)
			}
		}
	}
}

// goToolchainVars are the go command's own per-user locations. They default
// to paths under the profile (GOCACHE under LOCALAPPDATA on Windows, GOPATH
// and its module cache under the home, GOENV under APPDATA), so before the
// profile moves pinProcessToolHomes and pinToolHomesAt set each unset one
// to the value it resolves to now: a test that execs `go build` keeps the real caches and settings
// instead of rebuilding into, or downloading modules to, an empty temp home.
var goToolchainVars = []struct {
	name     string
	fallback func() string
}{
	{"GOCACHE", func() string {
		d, err := os.UserCacheDir()
		if err != nil {
			return ""
		}
		return filepath.Join(d, "go-build")
	}},
	{"GOPATH", defaultGOPATH},
	{"GOMODCACHE", func() string {
		p := os.Getenv("GOPATH")
		if p == "" {
			p = defaultGOPATH()
		}
		if p == "" {
			return ""
		}
		return filepath.Join(filepath.SplitList(p)[0], "pkg", "mod")
	}},
	{"GOENV", func() string {
		d, err := os.UserConfigDir()
		if err != nil {
			return ""
		}
		return filepath.Join(d, "go", "env")
	}},
}

// defaultGOPATH is the go command's default GOPATH: <home>/go.
func defaultGOPATH() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(h, "go")
}

// pinProcessToolHomes is TestMain's backstop: it pins every variable in
// toolHomeVars, for the whole process, to one new temp home (keeping the go
// toolchain's own locations where they are), and returns a cleanup that
// removes that home. Children the tests exec inherit the pin.
func pinProcessToolHomes() (func(), error) {
	for _, g := range goToolchainVars {
		if os.Getenv(g.name) != "" {
			continue
		}
		if v := g.fallback(); v != "" {
			if err := os.Setenv(g.name, v); err != nil {
				return nil, err
			}
		}
	}
	home, err := os.MkdirTemp("", "observer-test-home-")
	if err != nil {
		return nil, err
	}
	// The shared home's ~/.observer is a FILE, so no test can create or
	// open a default database (or any Observer state) there. This keeps
	// what internal/db.GuardLiveDB gave these tests before the pin: its
	// guarded roots are captured from the real home at package init, so
	// without the blocker a test that loads a missing config would open a
	// fresh default database here instead of being refused.
	if err := os.WriteFile(filepath.Join(home, ".observer"), []byte("cmd/observer test backstop: no default Observer state here\n"), 0o600); err != nil {
		return nil, err
	}
	env := toolHomeEnv(home)
	names := make([]string, 0, len(env))
	for name := range env {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		val := env[name]
		if val == "" {
			if err := os.Unsetenv(name); err != nil {
				return nil, err
			}
			continue
		}
		if err := os.Setenv(name, val); err != nil {
			return nil, err
		}
	}
	return func() { _ = os.RemoveAll(home) }, nil
}
