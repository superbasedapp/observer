//go:build !sbo_omit_integration_shell_wrap

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/shellwrap"
)

// TestShellWrapLaunchEnvTable pins `observer shell-wrap launch-env`, the
// answer a Windows bridge shim reads through wsl.exe (T-419): one row per
// outcome. The gates are substituted; nothing here starts a process, opens a
// socket or reads the real home.
func TestShellWrapLaunchEnvTable(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[proxy]\nport = 18821\n[observer]\ndb_path = \""+filepath.ToSlash(filepath.Join(dir, "o.db"))+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const url = "http://127.0.0.1:18821"
	allow := func(string, string, io.Writer) error { return nil }
	admitOK := func(context.Context, string, string, budgetLaunchEvidence) error { return nil }
	up := func(string, time.Duration) bool { return true }
	none := func() []string { return []string{"PATH=/usr/bin"} }

	tests := []struct {
		name       string
		id         string
		deps       launchEnvDeps
		wantOut    string
		wantErrHas string
		gateSaw    *string
	}{
		{
			"routed CLI row emits its variable", "claude-code",
			launchEnvDeps{refuseDisallowed: allow, admit: admitOK, reachable: up, environ: none},
			"SBO_ENV ANTHROPIC_BASE_URL " + url + "\nSBO_OK\n", "routing the Windows program via", nil,
		},
		{
			"the operator's own value wins", "claude-code",
			launchEnvDeps{
				refuseDisallowed: allow, admit: admitOK, reachable: up,
				environ: func() []string { return []string{"ANTHROPIC_BASE_URL=https://mine.example"} },
			},
			"SBO_OK\n", "already set in env; using yours", nil,
		},
		{
			"an unreachable proxy launches unrouted", "claude-code",
			launchEnvDeps{refuseDisallowed: allow, admit: admitOK, reachable: func(string, time.Duration) bool { return false }, environ: none},
			"SBO_OK\n", "not reachable", nil,
		},
		{
			"a suffix rides along", "opencode",
			launchEnvDeps{refuseDisallowed: allow, admit: admitOK, reachable: up, environ: none},
			"SBO_ENV OPENAI_BASE_URL " + url + "/v1\nSBO_OK\n", "", nil,
		},
		{
			"a config-file route has nothing to emit", "codex",
			launchEnvDeps{refuseDisallowed: allow, admit: admitOK, reachable: up, environ: none},
			"SBO_OK\n", "", nil,
		},
		{
			"the org disallow list refuses", "claude-code",
			launchEnvDeps{refuseDisallowed: func(_, tool string, w io.Writer) error {
				_, _ = io.WriteString(w, "refusing "+tool)
				return errors.New("disallowed")
			}, admit: admitOK, reachable: up, environ: none},
			"SBO_DENY\n", "refusing claude-code", nil,
		},
		{
			"a managed budget refuses", "claude-code",
			launchEnvDeps{refuseDisallowed: allow, admit: func(context.Context, string, string, budgetLaunchEvidence) error {
				return newVisibleLauncherError(errors.New("x"), "observer claude-code: refusing (budget)")
			}, reachable: up, environ: none},
			"SBO_DENY\n", "refusing (budget)", nil,
		},
		{
			"a GUI child-env row emits every variable", "vscode",
			launchEnvDeps{refuseDisallowed: allow, admit: admitOK, reachable: up, environ: none},
			"SBO_ENV ANTHROPIC_BASE_URL " + url + "\nSBO_ENV GOOGLE_GEMINI_BASE_URL " + url + "\nSBO_ENV OPENAI_BASE_URL " + url + "/v1\nSBO_OK\n", "", nil,
		},
		{
			"a stale id runs unrouted", "no-such-tool",
			launchEnvDeps{refuseDisallowed: allow, admit: admitOK, reachable: up, environ: none},
			"SBO_OK\n", "not a wrappable id", nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			if err := runShellWrapLaunchEnv(context.Background(), &out, &errb, cfgPath, tt.id, tt.deps); err != nil {
				t.Fatal(err)
			}
			if out.String() != tt.wantOut {
				t.Fatalf("stdout = %q, want %q (stderr %q)", out.String(), tt.wantOut, errb.String())
			}
			if tt.wantErrHas != "" && !strings.Contains(errb.String(), tt.wantErrHas) {
				t.Fatalf("stderr %q lacks %q", errb.String(), tt.wantErrHas)
			}
		})
	}
}

// TestShellWrapLaunchEnvGatesTheAdapter: a GUI row gates on the adapter that
// carries it (none for an editor host), a CLI row on its own key.
func TestShellWrapLaunchEnvGatesTheAdapter(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	var gated []string
	deps := launchEnvDeps{
		refuseDisallowed: func(_, tool string, _ io.Writer) error { gated = append(gated, tool); return nil },
		admit:            func(context.Context, string, string, budgetLaunchEvidence) error { return nil },
		reachable:        func(string, time.Duration) bool { return true },
		environ:          func() []string { return nil },
	}
	g, ok := integration.GUILaunchFor("cursor-ide")
	if !ok || g.Adapter == "" {
		t.Fatal("registry shape: cursor-ide must be adapter-carried")
	}
	for _, id := range []string{"claude-code", "cursor-ide", "vscode"} {
		if err := runShellWrapLaunchEnv(context.Background(), io.Discard, io.Discard, cfgPath, id, deps); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Join(gated, ",") != "claude-code,"+g.Adapter {
		t.Fatalf("gated %v", gated)
	}
}

func TestShellWrapLaunchEnvValueSafe(t *testing.T) {
	for _, ok := range []string{"http://127.0.0.1:8820", "http://localhost:8820/v1", "http://[::1]:8820/up/x"} {
		if !launchEnvValueSafe(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "a b", `a"b`, "a%b", "a&b", "a|b", "a^b", "a(b", "a>b", "a!b", "a\tb"} {
		if launchEnvValueSafe(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestShellWrapBridgeShimsTargetRealVerbs: every verb a WSL-bridge shim runs
// inside the distro is a real observer verb with passthrough args, and
// `shell-wrap launch-env` (what a Windows-program shim calls) is registered.
func TestShellWrapBridgeShimsTargetRealVerbs(t *testing.T) {
	root := newRootCmd()
	sw, _, err := root.Find([]string{"shell-wrap", "launch-env"})
	if err != nil || sw.Name() != "launch-env" || !sw.Hidden {
		t.Fatalf("`observer shell-wrap launch-env` is not a hidden registered command: %v", err)
	}
	h := shellwrap.Host{GOOS: "windows", Home: `C:\Users\u`, Bridge: &shellwrap.WSLBridge{Distro: "Ubuntu"}}
	sawWSL := false
	for _, c := range shellwrap.CandidatesOn(h) {
		if c.Side != shellwrap.SideWSL {
			continue
		}
		sawWSL = true
		w, _ := integration.WrappedCommandFor(c.ID)
		cmd, _, err := root.Find(w.Args)
		if err != nil || cmd == root || !cmd.DisableFlagParsing {
			t.Errorf("%s: a WSL-side shim runs `observer %s -- <args>`, which must be a passthrough verb", c.ID, strings.Join(w.Args, " "))
		}
	}
	if !sawWSL {
		t.Fatal("no WSL-side row on the bridge target (registry shape changed?)")
	}
}
