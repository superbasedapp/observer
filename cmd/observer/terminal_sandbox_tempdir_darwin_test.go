//go:build darwin && !sbo_omit_terminals_sandbox_seatbelt && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxenv"
)

// TestSeatbeltTempDirEnvDarwin builds the Seatbelt agent environment the
// host helper builds (D-UC1): the plan carries the tool's temp-dir names,
// and the agent gets each set to the run's TMPDIR, never the
// /private/tmp the profile hides, even when the user passed one.
func TestSeatbeltTempDirEnvDarwin(t *testing.T) {
	dirs := macRunDirs{TempDir: "/private/var/folders/x/T/obsbx-tmp/r1", SocketDir: "/private/var/folders/x/T/obsbx/r1/s"}
	plan := seatbeltPlanFile{Version: macPlanVersion, Dirs: dirs, TempDirEnv: sandboxenv.TempDirEnv("claude-code")}
	b, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	var back seatbeltPlanFile
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(back.TempDirEnv, []string{"CLAUDE_CODE_TMPDIR"}) {
		t.Fatalf("plan TempDirEnv = %q", back.TempDirEnv)
	}
	host := []string{
		"PATH=/usr/bin", "HOME=/Users/dev", "TMPDIR=/var/folders/x/T/",
		"CLAUDE_CODE_TMPDIR=/private/tmp",
		sandboxenv.EnvAllow + "=" + sandboxenv.Encode([]string{"CLAUDE_CODE_TMPDIR"}),
	}
	env := seatbeltAgentEnv(host, back.Dirs, 0, back.NativeEnv, back.TempDirEnv)
	var got []string
	for _, kv := range env {
		if strings.HasPrefix(kv, "CLAUDE_CODE_TMPDIR=") {
			got = append(got, kv)
		}
	}
	if want := []string{"CLAUDE_CODE_TMPDIR=" + dirs.TempDir}; !slices.Equal(got, want) {
		t.Errorf("CLAUDE_CODE_TMPDIR entries = %q, want %q", got, want)
	}
	if !slices.Contains(env, "TMPDIR="+dirs.TempDir+"/") {
		t.Errorf("the run's TMPDIR is missing from %q", env)
	}
	// A tool declaring nothing: no CLAUDE_CODE_TMPDIR at all when nobody
	// passed it.
	bare := seatbeltAgentEnv([]string{"PATH=/usr/bin"}, dirs, 0, nil, sandboxenv.TempDirEnv("codex"))
	for _, kv := range bare {
		if strings.HasPrefix(kv, "CLAUDE_CODE_TMPDIR=") {
			t.Errorf("an undeclared tool got %s", kv)
		}
	}
}
