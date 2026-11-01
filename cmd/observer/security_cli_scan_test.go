//go:build !sbo_omit_security

package main

import (
	"bytes"
	"errors"
	"testing"

	"github.com/spf13/cobra"
)

// TestSecurityScanIsOneCommand (live check macOS 2026-10-22, D3): `observer
// security scan --history` parses, and `security` has one scan command
// carrying every documented flag of both scans.
func TestSecurityScanIsOneCommand(t *testing.T) {
	sec := newSecurityCmd()
	var scans []*cobra.Command
	for _, c := range sec.Commands() {
		if c.Name() == "scan" {
			scans = append(scans, c)
		}
	}
	if len(scans) != 1 {
		t.Fatalf("security has %d scan commands, want 1", len(scans))
	}
	scan := scans[0]
	if err := scan.ParseFlags([]string{"--history", "--project", "/tmp/x", "--max-commits", "5", "--json", "--config", "/tmp/c.toml"}); err != nil {
		t.Fatalf("scan --history does not parse: %v", err)
	}
	want := []string{"history", "project", "max-commits", "json", "config"}
	if scan.Flags().Lookup("online") != nil {
		// The dependency scan is built: its flags stay too.
		want = append(want, "driver", "refresh-db", "online")
	}
	for _, f := range want {
		if scan.Flags().Lookup(f) == nil {
			t.Errorf("security scan has no --%s", f)
		}
	}
}

// TestMergeSecurityScanCmds: with both scans built, --history runs the
// history scan with the shared --json value and a DIR argument as its
// project, and without it the dependency scan runs.
func TestMergeSecurityScanCmds(t *testing.T) {
	run := func(args ...string) (string, error) {
		var ran string
		var histJSON bool
		var histProject string
		deps := &cobra.Command{Use: "scan [DIR]", RunE: func(*cobra.Command, []string) error { ran = "deps"; return nil }}
		deps.Flags().Bool("json", false, "")
		deps.Flags().Bool("online", false, "")
		hist := &cobra.Command{Use: "scan --history", RunE: func(*cobra.Command, []string) error {
			ran = "history"
			if histProject != "/repo" || !histJSON {
				return errors.New("the history scan did not get its flags")
			}
			return nil
		}}
		hist.Flags().Bool("history", false, "")
		hist.Flags().StringVar(&histProject, "project", "", "")
		hist.Flags().BoolVar(&histJSON, "json", false, "")
		parent := &cobra.Command{Use: "security"}
		parent.AddCommand(hist, deps)
		mergeSecurityScanCmds(parent)
		if n := len(parent.Commands()); n != 1 {
			t.Fatalf("%d scan commands", n)
		}
		var out bytes.Buffer
		parent.SetOut(&out)
		parent.SetErr(&out)
		parent.SetArgs(args)
		err := parent.Execute()
		return ran, err
	}
	if ran, err := run("scan", "--history", "--json", "/repo"); err != nil || ran != "history" {
		t.Fatalf("history: ran %q err %v", ran, err)
	}
	if ran, err := run("scan", "--online", "."); err != nil || ran != "deps" {
		t.Fatalf("deps: ran %q err %v", ran, err)
	}
}
