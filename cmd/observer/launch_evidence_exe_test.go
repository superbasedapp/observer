//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLaunchEvidenceExecutableIsAbsolute pins that the evidence a launcher
// hands the relay gate names its binary absolutely: a relative --claude-path
// (./agent.sh inside the workspace) was refused by boxLaunchEvidence as
// "executable" on the microVM row's second live run, so the tool never ran.
func TestLaunchEvidenceExecutableIsAbsolute(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "agent.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	abs := filepath.Join(dir, "agent.sh")
	for _, tc := range []struct {
		name string
		bin  string
		want []string
	}{
		{"dot relative", "./agent.sh", []string{abs, filepath.Join(real, "agent.sh")}},
		{"unclean relative", "sub/../agent.sh", []string{abs, filepath.Join(real, "agent.sh")}},
		{"absolute kept", abs, []string{abs}},
		{"empty kept", "", []string{""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := launchEvidenceExecutable(tc.bin)
			ok := false
			for _, w := range tc.want {
				if got == w {
					ok = true
				}
			}
			if !ok {
				t.Fatalf("launchEvidenceExecutable(%q) = %q, want one of %q", tc.bin, got, tc.want)
			}
			if _, err := boxLaunchEvidence(budgetLaunchEvidence{Executable: got}); err != nil {
				t.Fatalf("the relay gate refuses the evidence for %q: %v", tc.bin, err)
			}
		})
	}
}
