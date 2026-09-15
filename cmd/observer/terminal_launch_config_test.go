package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsession"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// terminal_launch_config_test.go pins the daemon `--config` propagation (Q1
// first-launch probe, P1) and the honest proxy-unreachable copy that rides with
// it. The defect: a dashboard-launched `observer <tool>` re-derived its config
// from the DEFAULT path, so on a daemon started with `--config <custom>` the
// child routed at the built-in :8820 instead of the config's `[proxy] port` and
// opened `~/.observer/observer.db` instead of the config's `db_path` — silently,
// while telling the operator to start a daemon that was already running.

// withDaemonConfigPath installs a daemon config path for one test and restores
// the previous value afterwards (the setting is process-wide).
func withDaemonConfigPath(t *testing.T, path string) {
	t.Helper()
	prev := daemonConfigPath()
	setDaemonConfigPath(path)
	t.Cleanup(func() { setDaemonConfigPath(prev) })
}

// daemonConfigFixture installs a platform-absolute daemon config path (the
// setting absolutizes what it is given, so a POSIX-looking literal would not
// survive verbatim on Windows) and returns it for the assertion.
func daemonConfigFixture(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "q1.toml")
	withDaemonConfigPath(t, p)
	return p
}

// TestLaunchConfigArgs pins the propagation decision itself: propagate the
// daemon's explicit path, add nothing when there is none, and never override a
// `--config` the caller already expressed for `observer` — while a `--config`
// that belongs to the launched TOOL (past a bare `--`) is a different program's
// flag and must not suppress ours.
func TestLaunchConfigArgs(t *testing.T) {
	tests := []struct {
		name    string
		cfgPath string
		extra   []string
		want    []string
	}{
		{"no daemon config — argv unchanged", "", nil, nil},
		{"no daemon config with caller args", "", []string{"--resume", "s1"}, nil},
		{"explicit daemon config", "/etc/observer/q1.toml", nil, []string{"--config", "/etc/observer/q1.toml"}},
		{"explicit daemon config alongside caller args", "/q1.toml", []string{"--resume", "s1"}, []string{"--config", "/q1.toml"}},
		{"caller already set --config", "/q1.toml", []string{"--config", "/other.toml"}, nil},
		{"caller already set --config=", "/q1.toml", []string{"--config=/other.toml"}, nil},
		{"tool's own --config past -- does not count", "/q1.toml", []string{"--", "--config", "tool.yaml"}, []string{"--config", "/q1.toml"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := launchConfigArgs(tt.cfgPath, tt.extra); !equalArgs(got, tt.want) {
				t.Fatalf("launchConfigArgs(%q, %v) = %v, want %v", tt.cfgPath, tt.extra, got, tt.want)
			}
		})
	}
}

// TestLaunchExtraArgsPrefixesDaemonConfig pins WHERE the flag lands: before the
// caller's tokens, so it can never fall past a bare `--` and be handed to the
// launched tool instead of to `observer <verb>`.
func TestLaunchExtraArgsPrefixesDaemonConfig(t *testing.T) {
	cfg := daemonConfigFixture(t)
	caller := []string{"--resume", "s1", "--", "--model", "opus"}
	got := launchExtraArgs(caller)
	want := []string{"--config", cfg, "--resume", "s1", "--", "--model", "opus"}
	if !equalArgs(got, want) {
		t.Fatalf("launchExtraArgs = %v, want %v", got, want)
	}
	// The caller's own slice must not have been mutated in place.
	if !equalArgs(caller, []string{"--resume", "s1", "--", "--model", "opus"}) {
		t.Fatalf("caller ExtraArgs mutated: %v", caller)
	}
}

// TestSetDaemonConfigPathAbsolutizes pins the cwd trap: a fresh launch spawns
// with the child's working directory set to the PROJECT root, so a relative
// `--config` handed on verbatim would resolve against the project instead of
// against the daemon's cwd where the operator typed it.
func TestSetDaemonConfigPathAbsolutizes(t *testing.T) {
	withDaemonConfigPath(t, "observer.toml")
	got := daemonConfigPath()
	if !filepath.IsAbs(got) {
		t.Fatalf("daemonConfigPath() = %q, want an absolute path", got)
	}
	if filepath.Base(got) != "observer.toml" {
		t.Fatalf("daemonConfigPath() = %q, want it to still name observer.toml", got)
	}
	// An empty setting stays empty — never the daemon's cwd.
	withDaemonConfigPath(t, "  ")
	if p := daemonConfigPath(); p != "" {
		t.Fatalf("daemonConfigPath() = %q for an unset flag, want \"\"", p)
	}
}

// TestStandaloneDashboardRecordsExplicitConfigBeforeStartup pins the command
// assembly: even when config loading fails, the dashboard records its explicit
// path before it could construct any terminal launch or Arena surface.
func TestStandaloneDashboardRecordsExplicitConfigBeforeStartup(t *testing.T) {
	prev := daemonConfigPath()
	t.Cleanup(func() { setDaemonConfigPath(prev) })
	cfgPath := filepath.Join(t.TempDir(), "invalid.toml")
	if err := os.WriteFile(cfgPath, []byte("[invalid\n"), 0o600); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}
	cmd := newDashboardCmd()
	cmd.SetArgs([]string{"--config", cfgPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("dashboard unexpectedly accepted invalid config")
	}
	if got := daemonConfigPath(); got != cfgPath {
		t.Fatalf("daemonConfigPath = %q, want dashboard config %q", got, cfgPath)
	}
}

// TestLaunchExtraArgsUnchangedWithoutDaemonConfig pins the default install:
// with no explicit `--config` the argv is byte-identical to before (CLAUDE.md
// #6 — additive, not invasive).
func TestLaunchExtraArgsUnchangedWithoutDaemonConfig(t *testing.T) {
	withDaemonConfigPath(t, "")
	caller := []string{"--no-proxy-route"}
	if got := launchExtraArgs(caller); !equalArgs(got, caller) {
		t.Fatalf("launchExtraArgs = %v, want %v", got, caller)
	}
	if got := launchExtraArgs(nil); got != nil {
		t.Fatalf("launchExtraArgs(nil) = %v, want nil", got)
	}
}

// spawnWithRecordingSpawner spawns req through a ptyLauncher over a fake spawner
// and returns the Spec the manager built.
func spawnWithRecordingSpawner(t *testing.T, req termsvc.LaunchRequest) termsession.Spec {
	t.Helper()
	sp := &recordingSpawner{}
	mgr := termsession.NewManager(termsession.Options{Spawner: sp, ReapInterval: time.Hour, Now: time.Now})
	t.Cleanup(mgr.Shutdown)
	launcher := &ptyLauncher{mgr: mgr, binPath: "/observer"}
	if _, err := launcher.Spawn(req); err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	return sp.lastSpec()
}

// TestPtyLauncherPropagatesDaemonConfigToFreshLaunch pins the fix at the seam
// the dashboard actually uses: a fresh launch — which carries NO ExtraArgs of
// its own, which is exactly why the bug was invisible — now carries the daemon's
// config path.
func TestPtyLauncherPropagatesDaemonConfigToFreshLaunch(t *testing.T) {
	cfg := daemonConfigFixture(t)
	spec := spawnWithRecordingSpawner(t, termsvc.LaunchRequest{Kind: termrun.KindFresh, Subcommand: "codex"})
	if !equalArgs(spec.ExtraArgs, []string{"--config", cfg}) {
		t.Fatalf("fresh ExtraArgs = %v, want [--config %s]", spec.ExtraArgs, cfg)
	}
}

// TestPtyLauncherPropagatesDaemonConfigToHandoffLaunch pins the same for a
// handoff launch, whose argv already carries `--continue-from <id>`: the flag
// rides in ExtraArgs, which lands after that pair and before any tool remainder.
func TestPtyLauncherPropagatesDaemonConfigToHandoffLaunch(t *testing.T) {
	cfg := daemonConfigFixture(t)
	spec := spawnWithRecordingSpawner(t, termsvc.LaunchRequest{
		Kind: termrun.KindHandoff, Subcommand: "claude", SessionID: "src-1",
	})
	if !equalArgs(spec.ExtraArgs, []string{"--config", cfg}) {
		t.Fatalf("handoff ExtraArgs = %v, want [--config %s]", spec.ExtraArgs, cfg)
	}
}

// TestPtyLauncherKeepsCallerConfigOverride pins the attach path's precedence:
// the CLI client's own `--config` is a deliberate per-launch intent and outranks
// the daemon-wide default, which must not be appended a second time.
func TestPtyLauncherKeepsCallerConfigOverride(t *testing.T) {
	daemonConfigFixture(t)
	spec := spawnWithRecordingSpawner(t, termsvc.LaunchRequest{
		Kind: termrun.KindAttach, Subcommand: "codex", ExtraArgs: []string{"--config", "/client.toml"},
	})
	if !equalArgs(spec.ExtraArgs, []string{"--config", "/client.toml"}) {
		t.Fatalf("attach ExtraArgs = %v, want the client's own [--config /client.toml]", spec.ExtraArgs)
	}
}

// TestPtyLauncherShellLaunchNeverCarriesDaemonConfig pins the pseudo-tool
// carve-out: `shell` runs the operator's shell, not `observer <verb>`, so an
// `observer` flag must never reach it. It holds by CONSTRUCTION — SpecShell's
// argv ignores ExtraArgs — which is what this asserts.
func TestPtyLauncherShellLaunchNeverCarriesDaemonConfig(t *testing.T) {
	daemonConfigFixture(t)
	spec := spawnWithRecordingSpawner(t, termsvc.LaunchRequest{
		Kind: termrun.KindFresh, Subcommand: "should-be-ignored", IsShell: true,
	})
	if spec.Kind != termsession.SpecShell {
		t.Fatalf("Kind = %v, want SpecShell", spec.Kind)
	}
	for _, a := range spec.ShellArgv {
		if strings.Contains(a, "--config") {
			t.Fatalf("shell argv carries an observer flag: %v", spec.ShellArgv)
		}
	}
}

// TestPtyLauncherSSHLaunchNeverCarriesDaemonConfig pins the same for an outbound
// SSH session, whose argv is composed entirely from an operator profile.
func TestPtyLauncherSSHLaunchNeverCarriesDaemonConfig(t *testing.T) {
	daemonConfigFixture(t)
	spec := spawnWithRecordingSpawner(t, termsvc.LaunchRequest{
		Kind: termrun.KindFresh, Subcommand: "should-be-ignored",
		SSHArgv: []string{"ssh", "host"},
	})
	if spec.Kind != termsession.SpecSSH {
		t.Fatalf("Kind = %v, want SpecSSH", spec.Kind)
	}
	if !equalArgs(spec.SSHArgv, []string{"ssh", "host"}) {
		t.Fatalf("SSHArgv = %v, want the profile argv verbatim", spec.SSHArgv)
	}
}

// TestProxyDownAdviceIsHonestForADaemonChild pins the copy half of P1: a child
// the daemon spawned must not be told to start a daemon that is demonstrably
// running — the remaining causes are the daemon's own `[proxy]` block, so that
// is what the advice names.
func TestProxyDownAdviceIsHonestForADaemonChild(t *testing.T) {
	child := proxyDownAdvice(true)
	if strings.Contains(child, "observer start") {
		t.Fatalf("daemon-child advice still tells the operator to start the daemon: %q", child)
	}
	if !strings.Contains(child, "[proxy]") {
		t.Fatalf("daemon-child advice names no actionable cause: %q", child)
	}
	bare := proxyDownAdvice(false)
	if !strings.Contains(bare, "observer start") {
		t.Fatalf("bare-launch advice = %q, want the `observer start` next step", bare)
	}
}

// TestProxyUnreachableNoticeShape pins the one-line notice a simple base-URL
// launcher prints: the tool, the URL it actually resolved, the consequence, and
// the honest next step — one line, no second explanation.
func TestProxyUnreachableNoticeShape(t *testing.T) {
	got := proxyUnreachableNotice("hermes", "http://127.0.0.1:18898", true)
	if strings.Count(got, "\n") != 0 {
		t.Fatalf("notice spans multiple lines: %q", got)
	}
	for _, want := range []string{"observer hermes:", "http://127.0.0.1:18898", "NOT captured", "[proxy]"} {
		if !strings.Contains(got, want) {
			t.Fatalf("notice %q missing %q", got, want)
		}
	}
}

// --- P2: one skipped route, one notice ---

// TestCodexRouteSkipNoticeIsOnePerOutcome pins the codex notice table: each
// reason a launch skips the `-c openai_base_url` override yields exactly one
// notice, and the proxy-down one never claims the `--no-proxy-route` flag the
// caller did not pass (the two-contradictory-notices defect, P2).
func TestCodexRouteSkipNoticeIsOnePerOutcome(t *testing.T) {
	tests := []struct {
		name        string
		reason      proxyFallbackReason
		daemonChild bool
		wantSubstr  []string
		denySubstr  []string
	}{
		{
			name:       "operator passed the flag",
			reason:     reasonNoProxyRouteClean,
			wantSubstr: []string{"--no-proxy-route set", "NOT captured"},
			denySubstr: []string{"not reachable"},
		},
		{
			name:       "launcher neutralized a down proxy",
			reason:     reasonProxyDownClean,
			wantSubstr: []string{"proxy not reachable at http://127.0.0.1:18898", "NOT captured", "observer start"},
			denySubstr: []string{"--no-proxy-route set"},
		},
		{
			name:        "down proxy inside a daemon-spawned terminal",
			reason:      reasonProxyDownClean,
			daemonChild: true,
			wantSubstr:  []string{"proxy not reachable", "[proxy]"},
			denySubstr:  []string{"--no-proxy-route set", "start it with"},
		},
		{
			name:       "unlisted reason falls back to the flag reading",
			reason:     reasonRouteHealthy,
			wantSubstr: []string{"--no-proxy-route set"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := codexRouteSkipNotice(tt.reason, "http://127.0.0.1:18898", tt.daemonChild)
			if strings.Count(got, "\n") != 0 {
				t.Fatalf("notice spans multiple lines: %q", got)
			}
			for _, w := range tt.wantSubstr {
				if !strings.Contains(got, w) {
					t.Fatalf("notice %q missing %q", got, w)
				}
			}
			for _, d := range tt.denySubstr {
				if strings.Contains(got, d) {
					t.Fatalf("notice %q must not contain %q", got, d)
				}
			}
		})
	}
}

// TestCodexProxyDownLaunchPrintsExactlyOneNotice walks the whole outcome the Q1
// probe hit — a dashboard launch, proxy down, NO `--no-proxy-route` flag, no
// persistent config route — from the fallback decision through the argv builder,
// and pins that it emits ONE stderr line, which does not claim a flag nobody
// passed.
func TestCodexProxyDownLaunchPrintsExactlyOneNotice(t *testing.T) {
	fb := decideProxyFallback(proxyFallbackInputs{
		noProxyRoute:    false, // the dashboard passes no escape hatch
		proxyReachable:  false, // and the proxy did not answer
		persistentRoute: false,
	})
	if fb.action != proxyNeutralize || fb.reason != reasonProxyDownClean {
		t.Fatalf("decision = (%v,%v), want (proxyNeutralize, reasonProxyDownClean)", fb.action, fb.reason)
	}

	var buf bytes.Buffer
	opts := codexLauncherOptions{stderr: &buf}
	// What runCodexLauncher's neutralize branch does: skip the route, carrying
	// the reason so the ONE notice tells the truth.
	opts.noProxyRoute = true
	opts.routeSkipReason = fb.reason

	args := codexLaunchArgs(opts, []string{"--model", "gpt-5"}, "http://127.0.0.1:18898")
	if !equalArgs(args, []string{"--model", "gpt-5"}) {
		t.Fatalf("codex argv = %v, want the user's args untouched (no -c override)", args)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly one notice for one skipped route, got %d:\n%s", len(lines), buf.String())
	}
	if strings.Contains(lines[0], "--no-proxy-route set") {
		t.Fatalf("notice claims a flag the caller never passed: %q", lines[0])
	}
	if !strings.Contains(lines[0], "proxy not reachable") {
		t.Fatalf("notice does not name the real cause: %q", lines[0])
	}
}

// TestCodexNoProxyRouteFlagStillPrintsItsOwnNotice pins the other row: when the
// operator DID pass the flag, the notice still says so.
func TestCodexNoProxyRouteFlagStillPrintsItsOwnNotice(t *testing.T) {
	fb := decideProxyFallback(proxyFallbackInputs{noProxyRoute: true})
	if fb.action != proxyNeutralize || fb.reason != reasonNoProxyRouteClean {
		t.Fatalf("decision = (%v,%v), want (proxyNeutralize, reasonNoProxyRouteClean)", fb.action, fb.reason)
	}
	var buf bytes.Buffer
	opts := codexLauncherOptions{stderr: &buf, noProxyRoute: true, routeSkipReason: fb.reason}
	codexLaunchArgs(opts, nil, "http://127.0.0.1:8820")
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly one notice, got %d:\n%s", len(lines), buf.String())
	}
	if !strings.Contains(lines[0], "--no-proxy-route set") {
		t.Fatalf("notice = %q, want the operator-flag reading", lines[0])
	}
}
