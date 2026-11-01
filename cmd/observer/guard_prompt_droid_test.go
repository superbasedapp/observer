package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGuardPromptStatusDroidReadsRegistrarsFile pins the droid row of
// `observer guard prompt status` (guard-enforcement fix, 2026-10-15): the
// probe reads the same ~/.factory/hooks.json the registrar writes, and an
// Observer entry written by ANOTHER working install of the binary (an
// `observer init` from elsewhere; `observer start` never refreshes droid's
// UserPromptSubmit, a binding still owed its live test) is reported
// REGISTERED, not NOT REGISTERED. A missing binary is still NOT REGISTERED.
// Not parallel: it sets HOME.
func TestGuardPromptStatusDroidReadsRegistrarsFile(t *testing.T) {
	cases := []struct {
		name      string
		oldExists bool
		want      string
	}{
		{"equivalent entry from another install", true, "REGISTERED ("},
		{"entry whose binary is gone", false, "NOT REGISTERED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := probeHookSetupHome(t)
			cfgPath, _ := writeGuardTestConfig(t)
			oldBin := filepath.Join(home, "old-install", "observer")
			newBin := filepath.Join(home, "new-install", "observer")
			for _, b := range []string{oldBin, newBin} {
				if err := os.MkdirAll(filepath.Dir(b), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(b, []byte("#!/bin/sh\n"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			probeHookRegister(t, home, oldBin, cfgPath, "droid")
			if raw, err := os.ReadFile(filepath.Join(home, ".factory", "hooks.json")); err != nil ||
				!strings.Contains(string(raw), "hook droid UserPromptSubmit") {
				t.Fatalf("registrar did not write ~/.factory/hooks.json: %v\n%s", err, raw)
			}
			if !tc.oldExists {
				if err := os.Remove(oldBin); err != nil {
					t.Fatal(err)
				}
			}
			var out bytes.Buffer
			printPromptWiredClientRow(&out, "droid", newBin, nil, cfgPath)
			got := out.String()
			if !strings.Contains(got, "droid") || !strings.Contains(got, tc.want) ||
				(tc.want == "REGISTERED (" && strings.Contains(got, "NOT REGISTERED")) {
				t.Fatalf("droid status = %q, want %q", got, tc.want)
			}
		})
	}
}
