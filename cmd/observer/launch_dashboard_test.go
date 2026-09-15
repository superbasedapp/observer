package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// recordingLauncher captures the fully server-derived LaunchRequest termsvc
// hands the Launcher, so a test can assert what project root actually reached
// the spawn boundary.
type recordingLauncher struct{ last termsvc.LaunchRequest }

func (r *recordingLauncher) Spawn(req termsvc.LaunchRequest) (string, error) {
	r.last = req
	return "H-1", nil
}

// TestCreateFreshTranslatesForeignProjectRoot pins the fresh-cwd fix
// (tool-binary-resolution arc §5): launchManagerAdapter.CreateFresh runs the
// client-influenced project root through crossmount.TranslateForeignPath BEFORE
// termsvc validates + spawns, so a Windows-drive-shaped root typed into the New
// Terminal dialog (`C:\Users\u\proj`) becomes its WSL-reachable `/mnt/c/...`
// form. A native absolute path is an identity no-op and must still reach the
// spawner unchanged.
func TestCreateFreshTranslatesForeignProjectRoot(t *testing.T) {
	dir := t.TempDir()
	lau := &recordingLauncher{}
	svc := termsvc.New(termsvc.Options{
		Recorder: assembledRecorder{},
		Launcher: lau,
		Policy: termsvc.Policy{
			AllowFresh:          true,
			AllowedTools:        []string{"claude-code"},
			AllowedProjectRoots: []string{dir},
		},
	})
	a := &launchManagerAdapter{svc: svc}

	// Native absolute path: translation is a no-op, so the canonical dir reaches
	// termsvc.Spawn unchanged (the regression guard that the translate call did
	// not break native launches).
	if _, err := a.CreateFresh(dashboard.FreshLaunchSpec{
		Tool: "claude-code", Subcommand: "claude", ProjectRoot: dir,
	}); err != nil {
		t.Fatalf("CreateFresh native: %v", err)
	}
	wantCanon, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if lau.last.Dir != wantCanon {
		t.Fatalf("native root not passed through: got %q want %q", lau.last.Dir, wantCanon)
	}

	// Pin the exact transform CreateFresh applies to a Windows drive root.
	const winRoot = `C:\Users\u\proj`
	if got := crossmount.TranslateForeignPath(winRoot); got != "/mnt/c/Users/u/proj" {
		t.Fatalf("transform pin: TranslateForeignPath(%q) = %q, want /mnt/c/Users/u/proj", winRoot, got)
	}

	// CreateFresh feeds the TRANSLATED path to termsvc; here it is neither
	// allow-listed nor existent, so validation denies it — proving the raw
	// backslash path was transformed + validated, never spawned verbatim.
	lau.last = termsvc.LaunchRequest{}
	if _, err := a.CreateFresh(dashboard.FreshLaunchSpec{
		Tool: "claude-code", Subcommand: "claude", ProjectRoot: winRoot,
	}); !errors.Is(err, dashboard.ErrLaunchProjectRootDenied) {
		t.Fatalf("CreateFresh windows root err = %v, want ErrLaunchProjectRootDenied", err)
	}
	if lau.last.Dir != "" {
		t.Fatalf("denied launch must not reach the spawner: got dir %q", lau.last.Dir)
	}
}

// TestToolPreflightSeam_ConfigOverrideParity pins F1: the dashboard preflight
// seam applies the SAME [launch.tools.<tool>].path override the actual launcher
// (resolveToolBin step 2) honors, so a preflight never diverges from the launch
// it predicts — in BOTH directions.
func TestToolPreflightSeam_ConfigOverrideParity(t *testing.T) {
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "claude")
	if err := os.WriteFile(binPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeCfg := func(t *testing.T, path string) string {
		t.Helper()
		cfgPath := filepath.Join(t.TempDir(), "config.toml")
		body := "[launch.tools.claude-code]\npath = " + strconv.Quote(path) + "\n"
		if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return cfgPath
	}

	// Direction 1: a configured, EXISTING path → verdict ok, Bin = that path,
	// note names the config key (parity with the launcher's configured-hit path).
	t.Run("configured_present_ok", func(t *testing.T) {
		seam := toolPreflightSeam(writeCfg(t, binPath), func() bool { return true })
		pf, ok := seam("claude-code")
		if !ok {
			t.Fatal("expected ok=true for a launchable tool")
		}
		if pf.Verdict != string(toolresolve.VerdictOK) || pf.Bin != binPath {
			t.Errorf("configured-present: got verdict=%q bin=%q, want ok / %q", pf.Verdict, pf.Bin, binPath)
		}
		if len(pf.Notes) == 0 || !strings.Contains(pf.Notes[0], "[launch.tools.claude-code].path") {
			t.Errorf("expected a note naming the config key, got %v", pf.Notes)
		}
	})

	// Direction 2: a configured, MISSING path → verdict not_found naming the
	// stale key, with NO silent fall-through to the ladder (which on this host
	// could resolve a real claude-code and dishonestly report ok).
	t.Run("configured_missing_not_found", func(t *testing.T) {
		missing := filepath.Join(binDir, "does-not-exist")
		seam := toolPreflightSeam(writeCfg(t, missing), func() bool { return true })
		pf, ok := seam("claude-code")
		if !ok {
			t.Fatal("expected ok=true (tool is launchable; the verdict carries the failure)")
		}
		if pf.Verdict != string(toolresolve.VerdictNotFound) {
			t.Errorf("configured-missing: verdict = %q, want not_found", pf.Verdict)
		}
		if pf.Bin != "" {
			t.Errorf("configured-missing: Bin should be empty, got %q", pf.Bin)
		}
		if len(pf.Notes) == 0 || !strings.Contains(pf.Notes[0], "[launch.tools.claude-code].path") {
			t.Errorf("expected a note naming the stale config key, got %v", pf.Notes)
		}
	})
}

func TestDashboardInstallPlanPrefersExactOS(t *testing.T) {
	hints := []integration.InstallHint{
		{Channel: "npm", Argv: []string{"npm", "install", "-g", "pkg"}, Display: "npm install -g pkg"},
		{OS: "linux", Channel: "brew", Argv: []string{"brew", "install", "pkg"}, Display: "brew install pkg"},
		{OS: "linux", Channel: "script", Argv: []string{"bash", "-lc", "vendor installer"}, Display: "vendor installer"},
	}
	got, ok := dashboardInstallPlanFor(hints, "linux", "/home/u", nil)
	if !ok {
		t.Fatal("expected an install plan")
	}
	if got.Display != "vendor installer" || strings.Join(got.Argv, "|") != "bash|-lc|vendor installer" {
		t.Fatalf("exact-OS plan did not win: %+v", got)
	}
}

// TestDashboardInstallPlanUsesUserLocalNPMPrefix pins the permission-safe npm
// rewrite AND its DI-04a companion: on a POSIX daemon the plan's argv[0] is the
// ABSOLUTE npm the merged PATH resolves (exec.Command in the install PTY honours
// only the daemon's own PATH, so a bare "npm" is exactly what failed), while the
// Display the operator reads keeps the short command. Paths are built with
// filepath.Join so the expectations hold on a Windows host too (the daemon GOOS
// under test is an argument, not the host's).
func TestDashboardInstallPlanUsesUserLocalNPMPrefix(t *testing.T) {
	hints := []integration.InstallHint{{
		Channel: "npm",
		Argv:    []string{"npm", "install", "-g", "--ignore-scripts", "pkg"},
		Display: "npm install -g --ignore-scripts pkg",
	}}
	home := filepath.Join(string(filepath.Separator)+"home", "azureuser")
	prefix := filepath.Join(home, ".local")
	npmBin := filepath.Join(string(filepath.Separator)+"opt", "node", "bin", "npm")
	look := func(name string) (string, bool) {
		if name != "npm" {
			return "", false
		}
		return npmBin, true
	}

	got, ok := dashboardInstallPlanFor(hints, "linux", home, look)
	if !ok {
		t.Fatal("expected an install plan")
	}
	want := strings.Join([]string{npmBin, "install", "--global", "--prefix", prefix, "--ignore-scripts", "pkg"}, "|")
	if strings.Join(got.Argv, "|") != want {
		t.Fatalf("argv = %v, want %s", got.Argv, want)
	}
	if got.Note != "" {
		t.Fatalf("a resolved argv[0] must carry no note, got %q", got.Note)
	}
	// Display stays the short, human command — the executed argv with its
	// program spelled the way the operator would type it, never the absolute
	// path DI-04a resolved.
	wantDisplay := displayInstallArgv(append([]string{"npm"}, got.Argv[1:]...))
	if got.Display != wantDisplay {
		t.Fatalf("display = %q, want %q", got.Display, wantDisplay)
	}
	if !strings.HasPrefix(got.Display, "npm install ") || strings.Contains(got.Display, " -g ") {
		t.Fatalf("display does not match the permission-safe short command: %q", got.Display)
	}

	// Unresolvable argv[0]: keep the bare name (LookPath on the daemon PATH is
	// the fallback) and say so honestly instead of dropping the plan.
	bare, ok := dashboardInstallPlanFor(hints, "linux", home, func(string) (string, bool) { return "", false })
	if !ok {
		t.Fatal("an unresolvable argv[0] must not drop the plan")
	}
	if bare.Argv[0] != "npm" {
		t.Fatalf("argv[0] = %q, want the bare name kept", bare.Argv[0])
	}
	if !strings.Contains(bare.Note, "npm") {
		t.Fatalf("note must name the missing program, got %q", bare.Note)
	}

	// Windows keeps the native `-g` plan AND the bare program: the spawner does
	// the PATHEXT-aware resolution there, so rewriting argv[0] here would only
	// bypass it.
	windows, ok := dashboardInstallPlanFor(hints, "windows", filepath.Join(`C:\Users`, "u"), look)
	if !ok || strings.Join(windows.Argv, "|") != "npm|install|-g|--ignore-scripts|pkg" {
		t.Fatalf("Windows npm plan must remain native: %+v ok=%v", windows, ok)
	}
	if windows.Note != "" {
		t.Fatalf("Windows plan must carry no argv[0] note, got %q", windows.Note)
	}
}

// TestDashboardNPMPlanPreservesValueFlags pins that the `--prefix` rewrite is a
// SUBSTITUTION of the global flag, not a filter: openclaw's grounded
// `--allow-scripts=openclaw` (and any other value-carrying flag) must survive
// verbatim, in place. Dropping it would silently skip the package's postinstall
// — the exact failure DI-12 grounded.
func TestDashboardNPMPlanPreservesValueFlags(t *testing.T) {
	hints := []integration.InstallHint{{
		Channel: "npm",
		Argv:    []string{"npm", "install", "-g", "--allow-scripts=openclaw", "openclaw@latest"},
		Display: "npm install -g --allow-scripts=openclaw openclaw@latest",
	}}
	home := filepath.Join(string(filepath.Separator)+"home", "u")
	got, ok := dashboardInstallPlanFor(hints, "linux", home, nil)
	if !ok {
		t.Fatal("expected an install plan")
	}
	want := strings.Join([]string{
		"npm", "install", "--global", "--prefix", filepath.Join(home, ".local"),
		"--allow-scripts=openclaw", "openclaw@latest",
	}, "|")
	if strings.Join(got.Argv, "|") != want {
		t.Fatalf("argv = %v, want %s", got.Argv, want)
	}
	if !strings.Contains(got.Display, "--allow-scripts=openclaw") {
		t.Fatalf("display dropped the value flag: %q", got.Display)
	}
}

// TestDashboardInstallChannelRankPrefersPackageManagersOverNPM pins the rank
// TABLE (CLAUDE.md #5): a vendor script wins, every OS package manager — brew,
// winget and the scoop row T2 grounded for opencode — shares one rank above the
// npm fallback. The set is exactly the closed Channel vocabulary's package
// managers (integration.InstallHint.Channel pinned by
// TestInstallHintChannelIsClosedVocabulary); "choco" is deliberately NOT in that
// vocabulary, so it is not asserted here.
func TestDashboardInstallChannelRankPrefersPackageManagersOverNPM(t *testing.T) {
	for _, ch := range []string{"brew", "winget", "scoop"} {
		if got := dashboardInstallChannelRank(ch); got != 1 {
			t.Errorf("rank(%q) = %d, want 1 (package managers rank together)", ch, got)
		}
	}
	if dashboardInstallChannelRank("script") >= dashboardInstallChannelRank("scoop") {
		t.Error("a vendor script must outrank a package manager")
	}
	if dashboardInstallChannelRank("scoop") >= dashboardInstallChannelRank("npm") {
		t.Error("a package manager must outrank the npm fallback")
	}

	hints := []integration.InstallHint{
		{OS: "windows", Channel: "npm", Argv: []string{"npm", "install", "-g", "pkg"}, Display: "npm install -g pkg"},
		{OS: "windows", Channel: "scoop", Argv: []string{"scoop", "install", "pkg"}, Display: "scoop install pkg"},
	}
	got, ok := dashboardInstallPlanFor(hints, "windows", `C:\Users\u`, nil)
	if !ok || got.Display != "scoop install pkg" {
		t.Fatalf("scoop must beat npm: %+v ok=%v", got, ok)
	}
}

// TestWindowsPlansForGroundedRowsAreNotNPM pins the DI-13 outcome T2 landed: on
// Windows the rows the research grounded a native channel for must resolve to
// that channel (script/winget/scoop), never fall through to the npm shim plan.
// It reads the LIVE registry, so a regression in the data is caught here.
func TestWindowsPlansForGroundedRowsAreNotNPM(t *testing.T) {
	for _, tool := range []string{
		"claude-code", "codex", "devin", "goose", "droid",
		"openclaw", "qwen-code", "pi",
	} {
		c, ok := integration.For(tool)
		if !ok || c.Binary == nil {
			t.Errorf("%s: no registry Binary row", tool)
			continue
		}
		plan, ok := dashboardInstallPlanFor(c.Binary.Installs, "windows", `C:\Users\u`, nil)
		if !ok {
			t.Errorf("%s: no Windows install plan", tool)
			continue
		}
		if plan.Argv[0] == "npm" {
			t.Errorf("%s: Windows plan falls back to npm (%q) — a grounded native channel should win",
				tool, plan.Display)
		}
	}
}

func TestDashboardOpenCodeInstallUsesOfficialLinuxInstaller(t *testing.T) {
	row, ok := integration.For("opencode")
	if !ok || row.Binary == nil {
		t.Fatal("opencode binary registry row missing")
	}
	got, ok := dashboardInstallPlanFor(row.Binary.Installs, "linux", "/home/u", nil)
	if !ok {
		t.Fatal("opencode Linux install plan missing")
	}
	if got.Display != "curl -fsSL https://opencode.ai/install | bash" {
		t.Fatalf("opencode plan = %q, want official user installer", got.Display)
	}
}

// TestDashResolveEnvTTL pins F7: the dashboard's toolresolve.Env is a TTL cache,
// not a forever-memo — it rebuilds via host env capture once the cached value
// ages past the TTL, so a fresh install becomes visible without a restart.
func TestDashResolveEnvTTL(t *testing.T) {
	prevNow, prevBuild, prevTTL := dashResolveEnvNow, dashResolveEnvBuild, dashResolveEnvTTL
	prevHave, prevAt, prevVal := dashResolveEnvHave, dashResolveEnvAt, dashResolveEnvVal
	t.Cleanup(func() {
		dashResolveEnvNow, dashResolveEnvBuild, dashResolveEnvTTL = prevNow, prevBuild, prevTTL
		dashResolveEnvHave, dashResolveEnvAt, dashResolveEnvVal = prevHave, prevAt, prevVal
	})

	var builds int
	dashResolveEnvBuild = func() toolresolve.Env { builds++; return toolresolve.Env{GOOS: "linux"} }
	now := time.Unix(1000, 0)
	dashResolveEnvNow = func() time.Time { return now }
	dashResolveEnvTTL = 30 * time.Second
	dashResolveEnvHave = false // cold cache

	dashResolveEnv()
	dashResolveEnv()
	if builds != 1 {
		t.Fatalf("expected exactly 1 build within TTL, got %d", builds)
	}
	now = now.Add(29 * time.Second) // still inside the TTL window
	dashResolveEnv()
	if builds != 1 {
		t.Fatalf("expected no rebuild before TTL expiry, got %d builds", builds)
	}
	now = now.Add(2 * time.Second) // 31s since the build → past TTL
	dashResolveEnv()
	if builds != 2 {
		t.Fatalf("expected a rebuild past TTL, got %d builds", builds)
	}
}

// TestTerminalLaunchPolicyAllowShell pins terminalLaunchPolicy's AllowShell
// wiring: it requires BOTH [terminal].enabled and [terminal.launch].allow_shell,
// and is independent of allow_fresh_agent — mirroring AllowFresh's own
// enabled-AND-opt-in gate, but as a SEPARATE opt-in (CLAUDE.md's "additive, not
// invasive" — a bare shell must not ride in on the AI-tool fresh-launch flag).
func TestTerminalLaunchPolicyAllowShell(t *testing.T) {
	tests := []struct {
		name            string
		enabled         bool
		allowFreshAgent bool
		allowShell      bool
		wantAllowFresh  bool
		wantAllowShell  bool
	}{
		{"terminal disabled denies both regardless of opt-ins", false, true, true, false, false},
		{"enabled, neither opt-in set", true, false, false, false, false},
		{"enabled, fresh-agent only", true, true, false, true, false},
		{"enabled, shell only", true, false, true, false, true},
		{"enabled, both opt-ins", true, true, true, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc2 := config.TerminalConfig{Enabled: tc.enabled}
			tc2.Launch.AllowFreshAgent = tc.allowFreshAgent
			tc2.Launch.AllowShell = tc.allowShell
			got := terminalLaunchPolicy(tc2)
			if got.AllowFresh != tc.wantAllowFresh {
				t.Errorf("AllowFresh = %v, want %v", got.AllowFresh, tc.wantAllowFresh)
			}
			if got.AllowShell != tc.wantAllowShell {
				t.Errorf("AllowShell = %v, want %v", got.AllowShell, tc.wantAllowShell)
			}
		})
	}
}

// TestMapFreshErrShellDisabled pins the error-translation seam: termsvc's
// ErrShellLaunchDisabled maps onto the dashboard's own sentinel, the same way
// every other termsvc fresh-launch authorization error does, so
// handleTerminalLaunch's switch (which only knows the dashboard sentinels)
// renders it as an honest 403 naming the missing config knob.
func TestMapFreshErrShellDisabled(t *testing.T) {
	got := mapFreshErr(termsvc.ErrShellLaunchDisabled)
	if !errors.Is(got, dashboard.ErrLaunchShellDisabled) {
		t.Fatalf("mapFreshErr(ErrShellLaunchDisabled) = %v, want ErrLaunchShellDisabled", got)
	}
}

// TestCreateFreshShellRequest pins launchManagerAdapter.CreateFresh's Shell
// plumbing end to end: a shell request is authorized by AllowShell alone (no
// AllowedTools entry needed — termsvc.ShellTool is deliberately never a member
// of that list), and the resulting LaunchRequest reaching the Launcher carries
// IsShell=true with the reserved pseudo-tool as its Tool label.
func TestCreateFreshShellRequest(t *testing.T) {
	lau := &recordingLauncher{}
	svc := termsvc.New(termsvc.Options{
		Recorder: assembledRecorder{},
		Launcher: lau,
		Policy: termsvc.Policy{
			AllowShell: true,
			// Deliberately no AllowFresh / AllowedTools — proves shell
			// authorization does not need the AI-tool fresh-launch gate.
		},
	})
	a := &launchManagerAdapter{svc: svc}

	if _, err := a.CreateFresh(dashboard.FreshLaunchSpec{
		Tool:  termsvc.ShellTool,
		Shell: true,
	}); err != nil {
		t.Fatalf("CreateFresh shell: %v", err)
	}
	if !lau.last.IsShell {
		t.Errorf("LaunchRequest.IsShell = false, want true: %+v", lau.last)
	}
	if lau.last.Tool != termsvc.ShellTool {
		t.Errorf("LaunchRequest.Tool = %q, want %q", lau.last.Tool, termsvc.ShellTool)
	}

	// Without AllowShell, the same request is denied even though it needs no
	// tool allow-list entry.
	svc2 := termsvc.New(termsvc.Options{Recorder: assembledRecorder{}, Launcher: lau})
	a2 := &launchManagerAdapter{svc: svc2}
	if _, err := a2.CreateFresh(dashboard.FreshLaunchSpec{Tool: termsvc.ShellTool, Shell: true}); !errors.Is(err, dashboard.ErrLaunchShellDisabled) {
		t.Fatalf("CreateFresh shell (disabled) err = %v, want ErrLaunchShellDisabled", err)
	}
}

// TestInstallNoteFor pins DI-03's honest-zero ladder: the sentence the New
// Terminal dialog shows when a tool has no guided install plan on this OS is
// registry-grounded when the row carries a reason, the shared vendor-docs
// sentence otherwise, and NEVER empty (an empty string is the dead-end the
// audit found).
func TestInstallNoteFor(t *testing.T) {
	tests := []struct {
		name string
		spec *integration.BinaryResolveSpec
		goos string
		want string
	}{
		{
			name: "nil_spec_falls_back_to_the_shared_sentence",
			spec: nil,
			goos: "linux",
			want: toolresolve.NoGroundedInstallMsg,
		},
		{
			name: "install_note_set_wins",
			spec: &integration.BinaryResolveSpec{InstallNote: "desktop installer only — no CLI channel exists"},
			goos: "linux",
			want: "desktop installer only — no CLI channel exists",
		},
		{
			name: "install_note_empty_falls_back_to_the_shared_sentence",
			spec: &integration.BinaryResolveSpec{},
			goos: "linux",
			want: toolresolve.NoGroundedInstallMsg,
		},
		{
			name: "blank_install_note_is_not_a_reason",
			spec: &integration.BinaryResolveSpec{InstallNote: "   "},
			goos: "darwin",
			want: toolresolve.NoGroundedInstallMsg,
		},
		{
			name: "windows_note_leads_when_the_row_has_no_windows_spelling",
			spec: &integration.BinaryResolveSpec{
				WindowsNote: "no Windows build exists (vendor: WSL only)",
				InstallNote: "install it inside WSL",
			},
			goos: "windows",
			want: "no Windows build exists (vendor: WSL only) — install it inside WSL",
		},
		{
			name: "windows_note_is_not_shown_off_windows",
			spec: &integration.BinaryResolveSpec{
				WindowsNote: "no Windows build exists (vendor: WSL only)",
				InstallNote: "install it inside WSL",
			},
			goos: "linux",
			want: "install it inside WSL",
		},
		{
			name: "windows_note_is_not_shown_when_a_windows_spelling_exists",
			spec: &integration.BinaryResolveSpec{
				Names:       integration.BinaryNames{Windows: []string{"tool.exe"}},
				WindowsNote: "stale note",
				InstallNote: "no winget package yet",
			},
			goos: "windows",
			want: "no winget package yet",
		},
		{
			name: "windows_note_alone_still_names_the_vendor_docs_floor",
			spec: &integration.BinaryResolveSpec{WindowsNote: "no Windows build exists"},
			goos: "windows",
			want: "no Windows build exists — " + toolresolve.NoGroundedInstallMsg,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := installNoteFor(tc.spec, tc.goos); got != tc.want {
				t.Fatalf("installNoteFor = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestToolPreflightSeamFillsInstallNoteWhenNoPlan pins the DI-03 wiring: when
// dashboardInstallPlanFor finds no plan for this OS the seam fills InstallNote
// (never leaving the dialog with a bare "not installed"), and when a plan DOES
// exist it fills InstallCommand and leaves InstallNote empty — the two are
// mutually exclusive by construction.
//
// The host env capture is replaced with a hermetic empty Env so the verdict is
// deterministic (nothing resolves) and no login shell is spawned.
func TestToolPreflightSeamFillsInstallNoteWhenNoPlan(t *testing.T) {
	prevBuild := dashResolveEnvBuild
	prevHave, prevAt, prevVal := dashResolveEnvHave, dashResolveEnvAt, dashResolveEnvVal
	t.Cleanup(func() {
		dashResolveEnvBuild = prevBuild
		dashResolveEnvHave, dashResolveEnvAt, dashResolveEnvVal = prevHave, prevAt, prevVal
	})
	dashResolveEnvBuild = func() toolresolve.Env { return toolresolve.Env{GOOS: runtime.GOOS} }
	dashResolveEnvHave = false

	// An empty (but present) config keeps the seam off step 1's
	// [launch.tools.<tool>].path override — and off the host's real config.
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	seam := toolPreflightSeam(cfgPath, func() bool { return true })

	var withPlan, withoutPlan string
	for _, c := range integration.Capabilities() {
		if !c.Handoff.Launchable() || c.Binary == nil {
			continue
		}
		if _, ok := dashboardInstallPlanFor(c.Binary.Installs, runtime.GOOS, dashboardInstallHome(), nil); ok {
			if withPlan == "" {
				withPlan = c.Tool
			}
		} else if withoutPlan == "" {
			withoutPlan = c.Tool
		}
	}

	if withoutPlan == "" {
		t.Logf("every launchable row has a %s install plan — nothing to assert for the no-plan arm", runtime.GOOS)
	} else {
		pf, ok := seam(withoutPlan)
		if !ok {
			t.Fatalf("seam(%q) reported not launchable", withoutPlan)
		}
		if pf.InstallCommand != "" {
			t.Errorf("%s has no plan yet carries install_command %q", withoutPlan, pf.InstallCommand)
		}
		if pf.InstallNote == "" {
			t.Errorf("%s has no install plan — install_note must state the reason", withoutPlan)
		}
	}

	if withPlan == "" {
		t.Skip("no launchable row has an install plan on this OS — nothing to assert for the plan arm")
	}
	pf, ok := seam(withPlan)
	if !ok {
		t.Fatalf("seam(%q) reported not launchable", withPlan)
	}
	if pf.InstallCommand == "" {
		t.Errorf("%s has an install plan — install_command must be set", withPlan)
	}
	if pf.InstallNote != "" {
		t.Errorf("%s has an install plan — install_note must stay empty, got %q", withPlan, pf.InstallNote)
	}
}
