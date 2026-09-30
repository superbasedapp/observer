package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// ideFake records what an `observer ide` launch did through its seams.
type ideFake struct {
	spawned    bool
	argv       []string
	dir        string
	env        []string
	admitted   []string
	disallowed []string
	admitErr   error
}

func (f *ideFake) deps(parentEnv []string) ideDeps {
	return ideDeps{
		spawn: func(argv []string, dir string, env []string) (*os.Process, error) {
			f.spawned, f.argv, f.dir, f.env = true, argv, dir, env
			return os.FindProcess(os.Getpid())
		},
		admit: func(_ context.Context, _ string, id string, ev budgetLaunchEvidence) error {
			f.admitted = append(f.admitted, id)
			if ev.Route != budgetLaunchRouteUnknown {
				return errors.New("GUI admission evidence must keep the route unknown")
			}
			return f.admitErr
		},
		refuseDisallowed: func(_ string, tool string, _ io.Writer) error {
			f.disallowed = append(f.disallowed, tool)
			return nil
		},
		reachable: func(string, time.Duration) bool { return true },
		environ:   func() []string { return parentEnv },
	}
}

// writeIDEConfig writes a scratch config pinning the proxy port and a fake
// executable for one GUI id via [launch.tools.<id>].path (the same override
// the dashboard GUI launch honours), and returns (configPath, fakeBin).
func writeIDEConfig(t *testing.T, id string, port int) (string, string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-app")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // test fixture executable
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.toml")
	body := "[proxy]\nport = " + strconv.Itoa(port) + "\n\n[launch.tools." + id + "]\npath = " + strconv.Quote(bin) + "\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg, bin
}

// TestRunIDELaunchWrapsAChildEnvHost is the end-to-end composition check with
// a fake exec: `observer ide vscode <dir> -- --new-window` spawns the resolved
// app with the project dir and the forwarded args, injects the host's routing
// variables at the configured proxy, keeps an operator-exported value, strips
// the daemon-internal child variables, and runs the budget admission under
// the GUI id without the adapter-disallow gate (a host has no adapter).
func TestRunIDELaunchWrapsAChildEnvHost(t *testing.T) {
	cfg, bin := writeIDEConfig(t, "vscode", 18777)
	project := t.TempDir()
	f := &ideFake{}
	parent := []string{
		"PATH=/usr/bin",
		"OPENAI_BASE_URL=https://mine.example/v1", // operator value wins
		"OBSERVER_OOB_AUTH=secret",                // daemon-internal, stripped
	}
	var stderr strings.Builder
	err := runIDELaunch(context.Background(), ideOptions{
		configPath: cfg, id: "vscode", projectDir: project,
		extraArgs: []string{"--new-window"}, stdout: io.Discard, stderr: &stderr,
	}, f.deps(parent))
	if err != nil {
		t.Fatalf("runIDELaunch: %v\n%s", err, stderr.String())
	}
	if !f.spawned {
		t.Fatal("app was not spawned")
	}
	if want := []string{bin, project, "--new-window"}; !reflect.DeepEqual(f.argv, want) {
		t.Errorf("argv = %q, want %q", f.argv, want)
	}
	if f.dir != project {
		t.Errorf("dir = %q, want %q", f.dir, project)
	}
	env := envMap(f.env)
	if got := env["ANTHROPIC_BASE_URL"]; got != "http://127.0.0.1:18777" {
		t.Errorf("ANTHROPIC_BASE_URL = %q", got)
	}
	if got := env["GOOGLE_GEMINI_BASE_URL"]; got != "http://127.0.0.1:18777" {
		t.Errorf("GOOGLE_GEMINI_BASE_URL = %q", got)
	}
	if got := env["OPENAI_BASE_URL"]; got != "https://mine.example/v1" {
		t.Errorf("OPENAI_BASE_URL = %q, want the operator's own value kept", got)
	}
	if _, leaked := env["OBSERVER_OOB_AUTH"]; leaked {
		t.Error("daemon-internal OBSERVER_OOB_AUTH leaked into the app env")
	}
	if !reflect.DeepEqual(f.admitted, []string{"vscode"}) {
		t.Errorf("admitted = %v, want [vscode]", f.admitted)
	}
	if len(f.disallowed) != 0 {
		t.Errorf("disallow gate consulted for a pure host: %v", f.disallowed)
	}
	out := stderr.String()
	for _, want := range []string{
		"OPENAI_BASE_URL already set in env; using yours",
		"live proof owed",
		"cold-start only",
		"per hosted agent:",
		"claude-code",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// TestRunIDELaunchNoWrapRowStillLaunches pins the honest path for a row with no
// base-URL surface: an adapter key resolves to its GUI row, the adapter-level
// disallow gate runs, the app still launches, nothing is injected, and the
// output says why.
func TestRunIDELaunchNoWrapRowStillLaunches(t *testing.T) {
	cfg, bin := writeIDEConfig(t, "cursor-ide", 18778)
	f := &ideFake{}
	var stderr strings.Builder
	err := runIDELaunch(context.Background(), ideOptions{
		configPath: cfg, id: "cursor", stdout: io.Discard, stderr: &stderr,
	}, f.deps([]string{"PATH=/usr/bin"}))
	if err != nil {
		t.Fatalf("runIDELaunch: %v", err)
	}
	if !f.spawned || f.argv[0] != bin {
		t.Fatalf("spawned=%v argv=%q, want the resolved cursor app", f.spawned, f.argv)
	}
	if env := envMap(f.env); env["OPENAI_BASE_URL"] != "" || env["ANTHROPIC_BASE_URL"] != "" {
		t.Errorf("a WrapNone row injected routing env: %v", f.env)
	}
	if !reflect.DeepEqual(f.disallowed, []string{"cursor"}) {
		t.Errorf("disallow gate = %v, want [cursor] (the carrying adapter)", f.disallowed)
	}
	if !reflect.DeepEqual(f.admitted, []string{"cursor-ide"}) {
		t.Errorf("admitted = %v, want [cursor-ide]", f.admitted)
	}
	if out := stderr.String(); !strings.Contains(out, "wrap: none - ") || strings.Contains(out, "live proof owed") {
		t.Errorf("output should state the grounded no-wrap reason and make no proof claim:\n%s", out)
	}
}

// TestRunIDELaunchRefusals pins the paths that must not spawn.
func TestRunIDELaunchRefusals(t *testing.T) {
	cfg, _ := writeIDEConfig(t, "vscode", 18779)
	notDir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		opts     ideOptions
		admitErr error
		wantErr  string
	}{
		{"unknown id", ideOptions{id: "no-such-app"}, nil, "unknown IDE / desktop app id"},
		{"ungrounded row is not offered", ideOptions{id: "hermes-desktop"}, nil, "is not offered for launch"},
		{"project dir must be a directory", ideOptions{id: "vscode", projectDir: notDir}, nil, "is not a directory"},
		{"budget admission refusal propagates", ideOptions{id: "vscode"}, errors.New("over budget"), "over budget"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &ideFake{admitErr: tt.admitErr}
			opts := tt.opts
			opts.configPath, opts.stdout, opts.stderr = cfg, io.Discard, io.Discard
			err := runIDELaunch(context.Background(), opts, f.deps(nil))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want one containing %q", err, tt.wantErr)
			}
			if f.spawned {
				t.Error("spawned despite the refusal")
			}
		})
	}
}

// TestRunIDELaunchDryRunTouchesNothing pins --dry-run: the plan and the
// per-agent routing are printed, but neither admission nor spawn runs.
func TestRunIDELaunchDryRunTouchesNothing(t *testing.T) {
	cfg, _ := writeIDEConfig(t, "vscode", 18780)
	f := &ideFake{}
	var stderr strings.Builder
	if err := runIDELaunch(context.Background(), ideOptions{
		configPath: cfg, id: "vscode", dryRun: true, stdout: io.Discard, stderr: &stderr,
	}, f.deps(nil)); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if f.spawned || len(f.admitted) != 0 || len(f.disallowed) != 0 {
		t.Fatalf("dry run had side effects: %+v", f)
	}
	if !strings.Contains(stderr.String(), "would launch Visual Studio Code") {
		t.Errorf("dry-run output:\n%s", stderr.String())
	}
}

// TestHostedRouteTextCoversEveryOutcome pins that every classified hosted
// outcome has operator copy, and that none of it uses an em-dash.
func TestHostedRouteTextCoversEveryOutcome(t *testing.T) {
	outcomes := []integration.HostedRoute{
		integration.HostedRoutePersisted, integration.HostedRouteLaunchEnv,
		integration.HostedRouteLauncherOnly, integration.HostedRouteManual,
		integration.HostedRouteUnproven, integration.HostedRouteNotRoutable,
	}
	if len(hostedRouteText) != len(outcomes) {
		t.Fatalf("hostedRouteText has %d rows, want %d", len(hostedRouteText), len(outcomes))
	}
	for _, o := range outcomes {
		f, ok := hostedRouteText[o]
		if !ok {
			t.Errorf("no operator copy for outcome %q", o)
			continue
		}
		for _, applied := range []bool{true, false} {
			txt := f(integration.HostedRouteRow{Tool: "x", Outcome: o, Routability: integration.RouteStatusProbeRequired, Launcher: "observer x"}, applied)
			if txt == "" || strings.ContainsRune(txt, '\u2014') {
				t.Errorf("outcome %q (applied=%v): copy %q is empty or uses an em-dash", o, applied, txt)
			}
		}
	}
}

// TestSplitDashArgs pins the positional / forwarded split.
func TestSplitDashArgs(t *testing.T) {
	tests := []struct {
		args      []string
		dash      int
		wantPos   []string
		wantExtra []string
	}{
		{[]string{"vscode", "."}, -1, []string{"vscode", "."}, nil},
		{[]string{"vscode", ".", "--new-window"}, 2, []string{"vscode", "."}, []string{"--new-window"}},
		{[]string{"--x"}, 0, []string{}, []string{"--x"}},
	}
	for _, tt := range tests {
		pos, extra := splitDashArgs(tt.args, tt.dash)
		if !reflect.DeepEqual(pos, tt.wantPos) || !reflect.DeepEqual(extra, tt.wantExtra) {
			t.Errorf("splitDashArgs(%q, %d) = (%q, %q), want (%q, %q)", tt.args, tt.dash, pos, extra, tt.wantPos, tt.wantExtra)
		}
	}
}
