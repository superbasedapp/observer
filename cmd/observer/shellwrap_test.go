package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/shellwrap"
)

// TestShellWrapShimsTargetRealVerbs pins that every command a shim can run is
// a real `observer` verb, and that every CLI launcher it runs forwards the
// operator's arguments after `--` untouched (the shim always inserts one, so
// `claude --help` reaches claude, not the wrapper's help).
func TestShellWrapShimsTargetRealVerbs(t *testing.T) {
	root := newRootCmd()
	byName := map[string]*cobra.Command{}
	for _, c := range root.Commands() {
		byName[c.Name()] = c
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, c := range shellwrap.Candidates(goos) {
			w, _ := integration.WrappedCommandFor(c.ID)
			cmd, ok := byName[w.Args[0]]
			if !ok {
				t.Fatalf("%s: shim runs `observer %s`, which is not a command", c.ID, w.Args[0])
			}
			if c.Kind == integration.LaunchKindTerminal && !cmd.DisableFlagParsing {
				t.Errorf("%s: `observer %s` parses its own flags, so the shim's `-- <args>` passthrough is not guaranteed", c.ID, w.Args[0])
			}
		}
	}
	if _, ok := byName["shell-wrap"]; !ok {
		t.Fatal("`observer shell-wrap` is not registered")
	}
	if _, clash := integration.ToolForLaunchSubcommand("shell-wrap"); clash {
		t.Fatal("shell-wrap collides with a launcher verb")
	}
}

// TestShellWrapCLIRoundTrip drives preview -> enable -> status -> disable
// against a throwaway HOME. The real home and shell files are never touched.
func TestShellWrapCLIRoundTrip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX layout")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/bash")
	t.Setenv("ZDOTDIR", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	bashrc := filepath.Join(home, ".bashrc")
	orig := "# mine\n"
	if err := os.WriteFile(bashrc, []byte(orig), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	cfg := filepath.Join(home, ".observer", "config.toml")
	var tool shellwrap.Candidate
	for _, c := range shellwrap.Candidates(runtime.GOOS) {
		if c.Kind == integration.LaunchKindTerminal {
			tool = c
			break
		}
	}
	run := func(args ...string) string {
		t.Helper()
		root := newRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs(append([]string{"shell-wrap"}, append(args, "--config", cfg)...))
		if err := root.Execute(); err != nil {
			t.Fatalf("shell-wrap %v: %v\n%s", args, err, out.String())
		}
		return out.String()
	}

	out := run("preview", tool.ID)
	if !strings.Contains(out, "dry run") || !strings.Contains(out, shellwrap.BlockBegin) {
		t.Fatalf("preview output:\n%s", out)
	}
	if b, _ := os.ReadFile(bashrc); string(b) != orig {
		t.Fatal("preview wrote the rc")
	}
	out = run("enable", tool.ID)
	if !strings.Contains(out, "applied") {
		t.Fatalf("enable output:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(home, ".observer", "shims", tool.Commands[0])); err != nil {
		t.Fatalf("shim not written: %v", err)
	}
	out = run("status")
	if !strings.Contains(out, "Command wrapping: on") || !strings.Contains(out, tool.HonestyText) {
		t.Fatalf("status output:\n%s", out)
	}
	run("disable")
	if b, _ := os.ReadFile(bashrc); string(b) != orig {
		t.Fatalf("disable did not restore the rc: %q", b)
	}
}

// TestShellWrapStartRefreshRepointsMovedShims drives `observer start`'s one
// shell-wrap call site against a throwaway HOME: silent and inert while
// wrapping is off, and when on, a shim baked with an old observer path is
// re-pointed at the running binary.
func TestShellWrapStartRefreshRepointsMovedShims(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX layout")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/bash")
	t.Setenv("ZDOTDIR", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	if err := os.WriteFile(filepath.Join(home, ".bashrc"), []byte(""), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	cfg := filepath.Join(home, ".observer", "config.toml")
	ctx := context.Background()

	var out, errb bytes.Buffer
	refreshShellWrapShims(ctx, &out, &errb, cfg)
	if out.Len() != 0 || errb.Len() != 0 {
		t.Fatalf("refresh with wrapping off must be silent: %q %q", out.String(), errb.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".observer", "shims")); !os.IsNotExist(err) {
		t.Fatalf("refresh with wrapping off created the shim dir: %v", err)
	}

	var tool shellwrap.Candidate
	for _, c := range shellwrap.Candidates(runtime.GOOS) {
		if c.Kind == integration.LaunchKindTerminal {
			tool = c
			break
		}
	}
	root := newRootCmd()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"shell-wrap", "enable", tool.ID, "--config", cfg})
	if err := root.Execute(); err != nil {
		t.Fatalf("enable: %v\n%s", err, out.String())
	}
	shim := filepath.Join(home, ".observer", "shims", tool.Commands[0])
	b, err := os.ReadFile(shim)
	if err != nil {
		t.Fatal(err)
	}
	baked, ok := shellwrap.EmbeddedObserverPath(string(b))
	if !ok {
		t.Fatalf("enable wrote an unparseable shim:\n%s", b)
	}
	// Simulate an install that moved: the shim names a path that is gone.
	stale := strings.Replace(string(b), "sbo_observer='"+baked+"'", "sbo_observer='/gone/prefix/observer'", 1)
	if err := os.WriteFile(shim, []byte(stale), 0o755); err != nil { //nolint:gosec // shims are executable
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	refreshShellWrapShims(ctx, &out, &errb, cfg)
	if errb.Len() != 0 || !strings.Contains(out.String(), "re-pointed") {
		t.Fatalf("refresh output %q / %q", out.String(), errb.String())
	}
	b, _ = os.ReadFile(shim)
	if got, _ := shellwrap.EmbeddedObserverPath(string(b)); got != baked {
		t.Fatalf("shim now runs %q, want %q", got, baked)
	}
}
