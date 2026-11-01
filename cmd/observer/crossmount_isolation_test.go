package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// stageRealHome stages an empty foreign root with discovery allowed and the
// account's real home pinned at HOME, so the production isolation rules
// apply in this test binary.
func stageRealHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	crossmount.StageForeignLayoutForTest(t, crossmount.ForeignLayoutForTest{Root: t.TempDir(), Discover: true, RealHome: home})
	return home
}

// TestCrossmountIsolationFromFlags: --no-crossmount, and a --config outside
// the real user home, each record the reason the doctor row names; a --config
// inside the real home records nothing (R-013).
func TestCrossmountIsolationFromFlags(t *testing.T) {
	cases := []struct {
		name string
		args func(home string) []string
		want string // substring of DetectionOffReason; "" = detection on
	}{
		{"no flags", func(string) []string { return nil }, ""},
		{"--no-crossmount", func(string) []string { return []string{"--no-crossmount"} }, "--no-crossmount was given"},
		{"--config inside the real home", func(h string) []string {
			return []string{"--config", filepath.Join(h, ".observer", "config.toml")}
		}, ""},
		{"--config outside the real home", func(string) []string {
			return []string{"--config", filepath.Join(t.TempDir(), "config.toml")}
		}, "--config"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home := stageRealHome(t)
			cmd, _, err := newRootCmd().Find([]string{"init"})
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.ParseFlags(c.args(home)); err != nil {
				t.Fatalf("flags %v do not parse on init: %v", c.args(home), err)
			}
			applyCrossmountIsolation(cmd)
			got := crossmount.DetectionOffReason()
			if c.want == "" && got != "" {
				t.Fatalf("DetectionOffReason() = %q, want detection on", got)
			}
			if c.want != "" && !strings.Contains(got, c.want) {
				t.Fatalf("DetectionOffReason() = %q, want it to name %q", got, c.want)
			}
		})
	}
}

// TestInitHelpDocumentsCrossmountIsolation: `observer init --help` states the
// isolation rule and lists the flag.
func TestInitHelpDocumentsCrossmountIsolation(t *testing.T) {
	var out bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetArgs([]string{"init", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--no-crossmount", "outside the real user home", crossmount.EnvDisableForeignHomes, "crossmount row"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("observer init --help lacks %q", want)
		}
	}
}

// TestEveryPersistentPreRunAppliesIsolation (LEFT2 audit S5): cobra runs
// only the nearest persistent pre-run, so every command in the tree that
// defines its own must be one this file knows calls the isolation step.
func TestEveryPersistentPreRunAppliesIsolation(t *testing.T) {
	known := map[string]bool{"observer": true, "observer sandbox hosted": true}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if (c.PersistentPreRunE != nil || c.PersistentPreRun != nil) && !known[c.CommandPath()] {
			t.Errorf("%s defines its own persistent pre-run; call applyCrossmountIsolation in it and add it here", c.CommandPath())
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(newRootCmd())
}
