package hook

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// S-17 early bugs (surface-gap lane w2-g): DimCode's DIMCODE_HOME and
// Dirac's DIRAC_DIR. Every row pins GOOS and the environment explicitly, and
// every path is built under t.TempDir(), so the table holds on any host.

var s17GOOSes = []string{"linux", "darwin", "windows"}

// TestDimCodeHomeOverrideFollowsVendorRule: DIMCODE_HOME is the home as-is
// when its last segment is already v2, else v2 is appended (the vendor
// binary's resolveCliHomeDirFromEnv, the rule internal/adapter/dimcode reads
// the store by). The old writer always appended v2, so a DIMCODE_HOME that
// ended in v2 was written to .../v2/v2/hooks.json, a file DimCode never
// reads.
func TestDimCodeHomeOverrideFollowsVendorRule(t *testing.T) {
	cases := []struct {
		name string
		env  func(alt string) string // DIMCODE_HOME; "" = unset
		want func(home, alt string) string
	}{
		{"unset", func(string) string { return "" }, func(home, _ string) string { return filepath.Join(home, ".dimcode", "v2") }},
		{"plain dir gets v2", func(alt string) string { return alt }, func(_, alt string) string { return filepath.Join(alt, "v2") }},
		{"already ends in v2", func(alt string) string { return filepath.Join(alt, "v2") }, func(_, alt string) string { return filepath.Join(alt, "v2") }},
		{"ends in v2 with a trailing separator", func(alt string) string { return filepath.Join(alt, "v2") + string(filepath.Separator) }, func(_, alt string) string { return filepath.Join(alt, "v2") }},
		{"v2 only inside the path", func(alt string) string { return filepath.Join(alt, "v2", "inner") }, func(_, alt string) string { return filepath.Join(alt, "v2", "inner", "v2") }},
	}
	for _, goos := range s17GOOSes {
		for _, tc := range cases {
			t.Run(goos+"/"+tc.name, func(t *testing.T) {
				home := t.TempDir()
				alt := filepath.Join(home, "alt")
				env := map[string]string{}
				if v := tc.env(alt); v != "" {
					env["DIMCODE_HOME"] = rowAbs(goos, v)
				}
				reg := waveRegistry(t, home, goos, env, false)
				res := reg.Register("dimcode")
				if res.Error != nil {
					t.Fatalf("register: %v", res.Error)
				}
				want := filepath.Join(tc.want(home, alt), "hooks.json")
				if filepath.Clean(res.ConfigPath) != want {
					t.Errorf("ConfigPath = %q, want %q", res.ConfigPath, want)
				}
				if _, err := os.Stat(want); err != nil {
					t.Errorf("hooks.json not written at %s: %v", want, err)
				}
				if _, err := os.Stat(filepath.Join(alt, "v2", "v2")); err == nil {
					t.Error("wrote under .../v2/v2, a directory DimCode never reads")
				}
				if un := reg.Unregister("dimcode"); un.Error != nil || len(un.HooksRemoved) == 0 {
					t.Errorf("unregister = %+v", un)
				}
			})
		}
	}
}

// diracScriptName is the per-event hook file name Dirac runs on goos.
func diracScriptName(goos, event string) string {
	if goos == "windows" {
		return event + ".ps1"
	}
	return event
}

// TestDimCodeRelativeHomeWritesNothing (FU-31): DimCode reads a relative
// DIMCODE_HOME against its own working directory, so the writer names no
// file and never falls back to ~/.dimcode/v2 (the old writer ignored the
// value and wrote the default home, which this DimCode does not read).
func TestDimCodeRelativeHomeWritesNothing(t *testing.T) {
	for _, goos := range s17GOOSes {
		t.Run(goos, func(t *testing.T) {
			home := t.TempDir()
			reg := waveRegistry(t, home, goos, map[string]string{"DIMCODE_HOME": filepath.Join("rel", "v2")}, false)
			if res := reg.Register("dimcode"); res.Error == nil || !strings.Contains(res.Error.Error(), "DIMCODE_HOME") {
				t.Fatalf("register = %+v, want an error naming DIMCODE_HOME", res)
			}
			if _, err := os.Stat(filepath.Join(home, ".dimcode")); !os.IsNotExist(err) {
				t.Errorf("the default home was written (err %v)", err)
			}
		})
	}
}

// TestDiracWritesHomeHooksWhateverDiracDir: Dirac's source builds the
// global Hooks folder on the OS home alone (getDiracHomePath =
// os.homedir()/.dirac; ensureDiracSubdir("Hooks")), so the writer puts its
// scripts in ~/.dirac/Hooks with or without DIRAC_DIR. The old writer used
// $DIRAC_DIR/Hooks, a folder the source never scans. Whether a run with
// DIRAC_DIR set scans ~/.dirac/Hooks is live check 32, so a relocated
// DIRAC_DIR yields a warning naming it, and DIRAC_DIR equal to ~/.dirac
// yields none.
func TestDiracWritesHomeHooksWhateverDiracDir(t *testing.T) {
	cases := []struct {
		name     string
		env      func(home, alt string) string // DIRAC_DIR; "" = unset
		wantWarn bool
	}{
		{"unset", func(string, string) string { return "" }, false},
		{"relocated", func(_, alt string) string { return alt }, true},
		{"the default home itself", func(home, _ string) string { return filepath.Join(home, ".dirac") }, false},
		{"relative value is ignored", func(string, string) string { return "rel-dirac" }, false},
	}
	for _, goos := range s17GOOSes {
		for _, tc := range cases {
			t.Run(goos+"/"+tc.name, func(t *testing.T) {
				home := t.TempDir()
				alt := filepath.Join(home, "alt")
				env := map[string]string{}
				if v := tc.env(home, alt); v != "" {
					env["DIRAC_DIR"] = v
				}
				reg := waveRegistry(t, home, goos, env, false)
				res := reg.Register("dirac")
				if res.Error != nil {
					t.Fatalf("register: %v", res.Error)
				}
				want := filepath.Join(home, ".dirac", "Hooks", diracScriptName(goos, "PreToolUse"))
				if filepath.Clean(res.ConfigPath) != want {
					t.Errorf("ConfigPath = %q, want %q", res.ConfigPath, want)
				}
				if _, err := os.Stat(want); err != nil {
					t.Errorf("script not in ~/.dirac/Hooks: %v", err)
				}
				if _, err := os.Stat(filepath.Join(alt, "Hooks")); err == nil {
					t.Error("wrote under $DIRAC_DIR/Hooks, which Dirac's source never scans")
				}
				warned := strings.Contains(strings.Join(res.Warnings, "\n"), "live check 32")
				if warned != tc.wantWarn {
					t.Errorf("live check 32 warning = %v, want %v (warnings %q)", warned, tc.wantWarn, res.Warnings)
				}
				dry := waveRegistry(t, home, goos, env, true).Register("dirac")
				if got := strings.Contains(strings.Join(dry.Warnings, "\n"), "live check 32"); got != tc.wantWarn {
					t.Errorf("dry run (the doctor's read) warning = %v, want %v", got, tc.wantWarn)
				}
			})
		}
	}
}

// TestDiracLegacyRelocatedScriptsKeptThenRemoved: scripts an earlier build
// wrote under $DIRAC_DIR/Hooks are reported and left in place by a register
// (removing either copy before live check 32 would guess which folder Dirac
// scans) and removed, with the new ones, by an unregister; a foreign file
// there is never touched.
func TestDiracLegacyRelocatedScriptsKeptThenRemoved(t *testing.T) {
	for _, goos := range s17GOOSes {
		t.Run(goos, func(t *testing.T) {
			home := t.TempDir()
			alt := filepath.Join(home, "alt")
			env := map[string]string{"DIRAC_DIR": alt}
			reg := waveRegistry(t, home, goos, env, false)
			legacyDir := filepath.Join(alt, "Hooks")
			legacy := reg.diracScripts(legacyDir, goos == "windows", "")
			if err := os.MkdirAll(legacyDir, 0o755); err != nil {
				t.Fatal(err)
			}
			for _, s := range legacy {
				if err := os.WriteFile(s.path, s.data, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			foreign := filepath.Join(legacyDir, diracScriptName(goos, "PostToolUse"))
			foreignBody := []byte("#!/bin/sh\necho mine\n")
			if err := os.WriteFile(foreign, foreignBody, 0o755); err != nil {
				t.Fatal(err)
			}

			res := reg.Register("dirac")
			if res.Error != nil {
				t.Fatalf("register: %v", res.Error)
			}
			joined := strings.Join(res.Warnings, "\n")
			if !strings.Contains(joined, "earlier build") || !strings.Contains(joined, diracScriptName(goos, "PreToolUse")) {
				t.Errorf("no note about the earlier build's scripts: %q", res.Warnings)
			}
			for _, s := range legacy {
				if got, err := os.ReadFile(s.path); err != nil || !bytes.Equal(got, s.data) {
					t.Errorf("register touched the earlier build's %s", s.path)
				}
			}

			un := reg.Unregister("dirac")
			if un.Error != nil {
				t.Fatalf("unregister: %v", un.Error)
			}
			for _, dir := range []string{filepath.Join(home, ".dirac", "Hooks"), legacyDir} {
				if _, err := os.Stat(filepath.Join(dir, diracScriptName(goos, "PreToolUse"))); err == nil {
					t.Errorf("unregister left Observer's script in %s", dir)
				}
			}
			if got, _ := os.ReadFile(foreign); !bytes.Equal(got, foreignBody) {
				t.Error("unregister touched a foreign hook file")
			}
			seen := map[string]int{}
			for _, ev := range un.HooksRemoved {
				seen[ev]++
			}
			if seen["PreToolUse"] != 1 {
				t.Errorf("HooksRemoved = %v, want PreToolUse exactly once", un.HooksRemoved)
			}
		})
	}
}
