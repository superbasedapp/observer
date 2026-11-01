//go:build linux && !sbo_omit_terminals_sandbox_landlock && !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox_seatbelt && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandboxenv"
	"github.com/marmutapp/superbased-observer/internal/sandboxlandlock"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// tempDirEnvBackends builds each backend's box environment that gives the
// run its own temp folder (D-UC1): the parent env and the tool's temp-dir
// names in, the environment out, plus the run's temp folder.
var tempDirEnvBackends = []struct {
	name string
	tmp  string
	env  func(parent, names []string) []string
}{
	{"seatbelt", "/var/folders/x/obsbx-tmp/r1", func(p, n []string) []string {
		return seatbeltAgentEnv(p, macRunDirs{TempDir: "/var/folders/x/obsbx-tmp/r1", SocketDir: "/var/folders/x/obsbx/r1/s"}, 0, nil, n)
	}},
	{"process_lite (landlock)", "/tmp/obsll/r1/tmp", func(p, n []string) []string {
		return landlockEnv(p, sandboxlandlock.PlanInput{TempDir: "/tmp/obsll/r1/tmp", SocketDir: "/tmp/obsll/r1/s"}, n)
	}},
	{"mxc-process", `C:\t\box\tmp`, func(p, n []string) []string {
		return mxcBoxEnv(p, `C:\t\box`, `C:\t\box\tmp`, vocab.TierInternet, 4242, "tok", n)
	}},
}

// tempDirParent is a launch environment whose user passed
// CLAUDE_CODE_TMPDIR (pass_env) pointing outside the box.
func tempDirParent() []string {
	return []string{
		"PATH=/usr/bin", "HOME=/home/dev",
		"CLAUDE_CODE_TMPDIR=/private/tmp",
		sandboxenv.EnvAllow + "=" + sandboxenv.Encode([]string{"CLAUDE_CODE_TMPDIR"}),
	}
}

// envValues is every value env holds for name (case-insensitive, as
// Windows reads it).
func envValues(env []string, name string) []string {
	var out []string
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && strings.EqualFold(k, name) {
			out = append(out, v)
		}
	}
	return out
}

// TestSandboxTempDirEnvPerBackend: on every backend that gives the run its
// own temp folder, a tool declaring a temp-dir variable gets it set to that
// folder exactly once, and the user's passed value never wins.
func TestSandboxTempDirEnvPerBackend(t *testing.T) {
	names := sandboxenv.TempDirEnv("claude-code")
	if len(names) == 0 {
		t.Fatal("claude-code declares no temp-dir variable")
	}
	for _, b := range tempDirEnvBackends {
		t.Run(b.name, func(t *testing.T) {
			env := b.env(tempDirParent(), names)
			for _, n := range names {
				if got := envValues(env, n); len(got) != 1 || got[0] != b.tmp {
					t.Errorf("%s = %q, want exactly [%q]", n, got, b.tmp)
				}
			}
		})
	}
}

// TestSandboxTempDirEnvNothingDeclared: a tool declaring nothing gets
// nothing extra on any backend: its environment equals the one built with
// no names, and a variable nobody passed stays absent.
func TestSandboxTempDirEnvNothingDeclared(t *testing.T) {
	names := sandboxenv.TempDirEnv("codex")
	if names != nil {
		t.Fatalf("codex declares %q; pick a tool that declares nothing", names)
	}
	parent := []string{"PATH=/usr/bin", "HOME=/home/dev", "CLAUDE_CODE_TMPDIR=/private/tmp"}
	for _, b := range tempDirEnvBackends {
		t.Run(b.name, func(t *testing.T) {
			got, base := b.env(parent, names), b.env(parent, nil)
			if strings.Join(got, "\n") != strings.Join(base, "\n") {
				t.Errorf("an undeclared tool's env changed:\n got %q\nwant %q", got, base)
			}
			if v := envValues(got, "CLAUDE_CODE_TMPDIR"); v != nil {
				t.Errorf("an unpassed CLAUDE_CODE_TMPDIR reached the box: %q", v)
			}
		})
	}
}

// TestSandboxTempDirTableRowsAreLaunchable: every row of the temp-dir table
// names a registry tool that is sandbox-launchable, so no row is dead data.
func TestSandboxTempDirTableRowsAreLaunchable(t *testing.T) {
	for _, r := range sandboxenv.TempDirTable() {
		c, ok := integration.For(r.Tool)
		if !ok {
			t.Errorf("temp-dir row %q is not a registry tool", r.Tool)
			continue
		}
		if len(c.Sandbox.StateRW) == 0 {
			t.Errorf("temp-dir row %q is not sandbox-launchable", r.Tool)
		}
	}
}
