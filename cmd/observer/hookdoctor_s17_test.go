package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestHookDoctorShowsDiracRelocationUnknown pins the doctor half of S-17's
// Dirac fix: with DIRAC_DIR relocated, `observer doctor --hooks` reads the
// writer with the same environment `observer init` writes with, and each
// Dirac binding check carries the writer's note that a run with DIRAC_DIR
// set scanning ~/.dirac/Hooks is unverified (live check 32). The verdict
// itself is unchanged by the note. Before the fix the doctor read the
// writers with no environment and dropped their warnings.
//
// Every path is under t.TempDir(): HOME and USERPROFILE are pinned, and the
// Windows home the bridge target would read is an empty directory inside the
// pinned home, so no real profile is read.
func TestHookDoctorShowsDiracRelocationUnknown(t *testing.T) {
	sandbox := t.TempDir()
	home := filepath.Join(sandbox, "home")
	win := filepath.Join(home, "mnt", "c", "Users", "operator")
	for _, d := range []string{home, win} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	orig := hookRegistrationOptions
	t.Cleanup(func() { hookRegistrationOptions = orig })
	hookRegistrationOptions = func(binary, configPath string) hook.Options {
		o := orig(binary, configPath)
		o.HomeDir, o.WSLDistro, o.WindowsUserHome = home, "Ubuntu", win
		// A pinned HomeDir reads no relocation variable (crossmount.HomeEnv,
		// R-188 F1); production pins none and reads DIRAC_DIR, so the test
		// that stands in for it injects the environment explicitly.
		o.Getenv = os.Getenv
		return o
	}
	c, ok := integration.For("dirac")
	if !ok {
		t.Fatal("dirac is not a registry row")
	}
	var b integration.HookBinding
	for _, cand := range c.Hook.Bindings {
		if cand.Registered {
			b = cand
			break
		}
	}
	if b.NativeEvent == "" {
		t.Fatal("dirac has no registered binding")
	}
	binary := filepath.Join(home, "bin", "observer")
	configPath := filepath.Join(home, ".observer", "config.toml")

	for _, tc := range []struct {
		name     string
		diracDir string
		wantNote bool
	}{
		{"unset", "", false},
		{"relocated", filepath.Join(sandbox, "dirac-alt"), true},
		{"the default home itself", filepath.Join(home, ".dirac"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DIRAC_DIR", tc.diracDir)
			homes := readHookHomeEvents(binary, configPath, "dirac")
			want := filepath.Join(home, ".dirac", "Hooks")
			if len(homes) == 0 || !strings.HasPrefix(homes[0].detail, want) {
				t.Fatalf("doctor read %+v, want the writer's path under %s", homes, want)
			}
			ck, _ := bindingCheck(c, b, "dirac", homes, diag.HookTrust{}, map[string]diag.Check{})
			got := strings.Contains(strings.Join(ck.Details, "\n"), "live check 32")
			if got != tc.wantNote {
				t.Fatalf("live check 32 note = %v, want %v; details %q", got, tc.wantNote, ck.Details)
			}
			if _, err := os.Stat(want); err == nil {
				t.Error("the doctor's dry-run read wrote the Hooks folder")
			}
		})
	}
}
