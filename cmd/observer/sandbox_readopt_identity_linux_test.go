//go:build linux && !sbo_omit_terminals_sandbox_oci_readopt && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// TestReadoptRekeyKeepsTerminalRun pins F-053 at the re-key itself: the
// compose kept facts with no terminal run (it runs before the launcher's
// bind), the run's record was bound afterwards, and the re-keyed record
// carries that bound terminal run with new secrets.
func TestReadoptRekeyKeepsTerminalRun(t *testing.T) {
	for _, tc := range []struct {
		name, kept, bound, want string
	}{
		{"kept empty, record bound", "", f053TerminalRun, f053TerminalRun},
		{"kept set", f053TerminalRun, f053TerminalRun, f053TerminalRun},
		{"never bound", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obs := t.TempDir()
			rec, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{RunID: f053ContainerRun, Tool: "claude-code", ProjectRoot: obs, WorkspaceDir: obs, Roots: []string{obs}})
			if err != nil {
				t.Fatal(err)
			}
			if err := sandboxrelayd.WriteRun(obs, rec); err != nil {
				t.Fatal(err)
			}
			if tc.bound != "" {
				if err := sandboxrelayd.BindTerminalRun(obs, f053ContainerRun, tc.bound); err != nil {
					t.Fatal(err)
				}
			}
			kept := readoptKept{V: readoptVersion, RunID: f053ContainerRun, Facts: readoptFacts{Tool: "claude-code", ProjectRoot: obs, WorkspaceDir: obs, Roots: []string{obs}, TerminalRunID: tc.kept}}
			if err := readoptRekey(obs, kept); err != nil {
				t.Fatal(err)
			}
			got, err := sandboxrelayd.ReadRun(obs, f053ContainerRun)
			if err != nil {
				t.Fatal(err)
			}
			if got.TerminalRunID != tc.want {
				t.Fatalf("re-keyed record terminal run %q, want %q", got.TerminalRunID, tc.want)
			}
			if string(got.LinkSecret) == string(rec.LinkSecret) {
				t.Fatal("the re-key kept the old link secret")
			}
		})
	}
}
