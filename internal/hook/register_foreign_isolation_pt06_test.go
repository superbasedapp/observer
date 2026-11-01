package hook

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// PT-06 (plans decision log task row; joint roadmap section 11 item 9): a Go
// test registered hooks into the laptop's REAL Windows home
// (~/.qwen/settings.json, ~/.qoder/settings.json, ~/.gemini/settings.json,
// ~/.factory/hooks.json), pointing them at a long-gone observer.test. The
// cause is closed by crossmount's test-binary guard (incident 2026-10-02);
// this pins it for the four writers that incident reached and the
// claude-code-windows bridge target: an UNPINNED registry (the shape
// `observer start` uses) under a temp HOME, with a detectable,
// ownership-proven fake /mnt/c/Users tree present, writes nothing outside
// HOME. The control lifts discovery for the staged root only and shows the
// same fixture IS written, so the fixture is detectable and the writers
// honour crossmount's suppression answer. What the guarded subtest
// exercises is the staged-layout rule (a staged layout with Discover false
// suppresses foreign homes on its own, rule 1 of foreignSuppressedWith),
// not the test-binary guard or the OBSERVER_CROSSMOUNT_DISABLE knob; those
// are pinned at the source by
// internal/platform/crossmount/testguard_test.go
// (TestDefaultDetectorGuardHoldsWithForeignHomePresent and
// TestEnvDisableForeignHomesSuppressesDetector), and the knob's export by
// TestHookTestsExportTheCrossmountKnob below. Not parallel: it sets HOME
// and stages process-wide crossmount state.

// pt06Writers are the writers PT-06 names (droid writes ~/.factory/hooks.json)
// and their -windows bridge targets, plus the Claude Code bridge.
var pt06Writers = []string{
	"qwen-code", "qoder", "gemini-cli", "droid",
	"qwen-code-windows", "qoder-windows", "gemini-cli-windows", "droid-windows",
	"claude-code-windows",
}

// pt06ForeignDirs are the vendor directories present in the fake Windows home.
var pt06ForeignDirs = []string{".qwen", ".qoder", ".gemini", ".factory", ".claude"}

// pt06Fixture is the sandbox: HOME, the fake Windows users root and the
// operator's Windows home inside it.
type pt06Fixture struct {
	sandbox, home, usersRoot, winHome string
}

func newPT06Fixture(t *testing.T, discover bool) pt06Fixture {
	t.Helper()
	const winUser = "operator"
	sandbox := t.TempDir()
	f := pt06Fixture{
		sandbox:   sandbox,
		home:      filepath.Join(sandbox, "home"),
		usersRoot: filepath.Join(sandbox, "mnt", "c", "Users"),
	}
	f.winHome = filepath.Join(f.usersRoot, winUser)
	if err := os.MkdirAll(f.home, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range pt06ForeignDirs {
		if err := os.MkdirAll(filepath.Join(f.winHome, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	seeds := map[string]string{
		"NTUSER.DAT":                              "hive",
		filepath.Join(".qwen", "settings.json"):   `{"sentinel":"operator-owned"}`,
		filepath.Join(".qoder", "settings.json"):  `{"sentinel":"operator-owned"}`,
		filepath.Join(".gemini", "settings.json"): `{"sentinel":"operator-owned"}`,
		filepath.Join(".factory", "hooks.json"):   `{"sentinel":"operator-owned"}`,
		filepath.Join(".claude", "settings.json"): `{"hooks":{},"sentinel":"operator-owned"}`,
	}
	for rel, body := range seeds {
		if err := os.WriteFile(filepath.Join(f.winHome, rel), []byte(body+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", f.home)
	t.Setenv("USERPROFILE", f.home)
	t.Setenv("WSL_DISTRO_NAME", "TestDistro")
	crossmount.StageForeignLayoutForTest(t, crossmount.ForeignLayoutForTest{Root: f.usersRoot, WindowsUser: winUser, Discover: discover})
	return f
}

// treeDigest maps every file under root to a digest of its bytes.
func treeDigest(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		s := sha256.Sum256(b)
		out[p] = hex.EncodeToString(s[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// pt06Register runs each writer through an unpinned registry, as
// `observer start` builds it.
func pt06Register(t *testing.T) map[string]RegistrationResult {
	t.Helper()
	r, err := NewRegistry(Options{BinaryPath: "/opt/observer/bin/observer"})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]RegistrationResult{}
	for _, target := range pt06Writers {
		out[target] = r.Register(target)
	}
	return out
}

func TestPT06RegistrationUnderATempHomeWritesNothingOutsideIt(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the -windows bridge targets only exist for a Linux (WSL) daemon")
	}

	// The staged layout (Discover false) is what suppresses the fake
	// foreign home here, through foreignSuppressedWith's staged-layout
	// rule; the test-binary guard itself is pinned in
	// internal/platform/crossmount/testguard_test.go.
	t.Run("guarded: nothing outside HOME changes", func(t *testing.T) {
		f := newPT06Fixture(t, false)
		before := treeDigest(t, f.sandbox)
		results := pt06Register(t)
		after := treeDigest(t, f.sandbox)
		for p, sum := range after {
			if crossmount.PathUnder(f.home, p) {
				continue
			}
			if before[p] != sum {
				t.Errorf("a registration under a temp HOME wrote %s, outside HOME", p)
			}
		}
		for p := range before {
			if _, ok := after[p]; !ok && !crossmount.PathUnder(f.home, p) {
				t.Errorf("a registration under a temp HOME removed %s, outside HOME", p)
			}
		}
		for target, res := range results {
			if res.ConfigPath != "" && !crossmount.PathUnder(f.home, res.ConfigPath) {
				t.Errorf("%s reports config %s, outside HOME", target, res.ConfigPath)
			}
			if strings.HasSuffix(target, "-windows") && len(res.HooksAdded) > 0 {
				t.Errorf("%s added %v under the guard", target, res.HooksAdded)
			}
		}
		// Non-vacuous: the native writers did register into HOME.
		for _, target := range []string{"qwen-code", "qoder", "gemini-cli", "droid"} {
			if res := results[target]; res.Error != nil || len(res.HooksAdded) == 0 {
				t.Errorf("%s did not register into the temp HOME (%v, %v); the test must exercise a live write", target, res.Error, res.HooksAdded)
			}
		}
	})

	t.Run("control: discovery allowed for the staged root writes there", func(t *testing.T) {
		f := newPT06Fixture(t, true)
		results := pt06Register(t)
		for _, target := range []string{"qwen-code-windows", "qoder-windows", "gemini-cli-windows", "droid-windows", "claude-code-windows"} {
			res := results[target]
			if res.Error != nil || !crossmount.PathUnder(f.winHome, res.ConfigPath) {
				t.Fatalf("control %s: config %q, error %v; the fixture is not detectable, so the guarded subtest proves nothing", target, res.ConfigPath, res.Error)
			}
			b, err := os.ReadFile(res.ConfigPath)
			if err != nil || !strings.Contains(string(b), "wsl.exe -d TestDistro") {
				t.Errorf("control %s: %s lacks the wsl.exe bridge (%v)", target, res.ConfigPath, err)
			}
		}
	})
}

// TestHookTestsExportTheCrossmountKnob: internal/hook's TestMain exports
// OBSERVER_CROSSMOUNT_DISABLE for the whole run, as cmd/observer's does, so a
// real observer binary a test here might exec inherits it and never resolves
// the operator's real Windows home (PT-06).
func TestHookTestsExportTheCrossmountKnob(t *testing.T) {
	if got := os.Getenv(crossmount.EnvDisableForeignHomes); got != "1" {
		t.Fatalf("%s = %q in internal/hook's tests, want \"1\" (TestMain)", crossmount.EnvDisableForeignHomes, got)
	}
}
