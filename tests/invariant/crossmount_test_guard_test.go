package invariant

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCrossmountTestGuard_StructuralPins pins the incident-2026-10-02 guard:
// a cmd/observer test faked HOME, called autoRegisterHooks, and rewrote the
// operator's REAL /mnt/c/Users/<u>/.claude/settings.json because foreign-OS
// home discovery is keyed off fixed mount points, not $HOME. The behavioural
// tests (internal/platform/crossmount/testguard_test.go,
// cmd/observer/start_foreign_isolation_test.go) prove the guard works; this
// one fails if a refactor hollows it out or drops a call site.
func TestCrossmountTestGuard_StructuralPins(t *testing.T) {
	root := repoRoot(t)
	pins := []struct {
		file string // repo-relative
		want []string
	}{
		{
			filepath.Join("internal", "platform", "crossmount", "testguard.go"),
			[]string{"testing.Testing()", "EnvDisableForeignHomes", "AllowLiveForeignHomesInTestEnv", "func StageForeignLayoutForTest(", "func ForeignHomesSuppressed("},
		},
		{
			// The default detector derives suppression from the guard, and the
			// scan honours it before enumerating any foreign root.
			filepath.Join("internal", "platform", "crossmount", "crossmount.go"),
			[]string{"suppressForeign: foreignSuppressedWith(staged, os.Getenv(EnvDisableForeignHomes), testBinaryGuard)", "if d.suppressForeign {"},
		},
		{
			// The ownership probe must not exec cmd.exe while suppressed.
			filepath.Join("internal", "platform", "crossmount", "windowsuser.go"),
			[]string{"foreignSuppressedWith(nil, os.Getenv(EnvDisableForeignHomes), testBinaryGuard)"},
		},
		{
			// Spawned REAL binaries are not test binaries: the harness env must
			// carry the knob.
			filepath.Join("tests", "e2e", "statusline", "statusline_e2e_test.go"),
			[]string{"crossmount.EnvDisableForeignHomes + \"=1\""},
		},
		{
			filepath.Join("tests", "e2e", "oneshot", "oneshot_e2e_test.go"),
			[]string{"crossmount.EnvDisableForeignHomes + \"=1\""},
		},
		{
			filepath.Join("cmd", "observer", "testmain_test.go"),
			[]string{"os.Setenv(crossmount.EnvDisableForeignHomes, \"1\")"},
		},
	}
	for _, p := range pins {
		t.Run(p.file, func(t *testing.T) {
			src, err := os.ReadFile(filepath.Join(root, p.file))
			if err != nil {
				t.Fatalf("read %s: %v", p.file, err)
			}
			for _, w := range p.want {
				if !strings.Contains(string(src), w) {
					t.Errorf("%s no longer contains %q — the crossmount test guard (incident 2026-10-02) has been weakened", p.file, w)
				}
			}
		})
	}
}

// TestCmdObserverTestMainIsUntagged (RB1 gate): cmd/observer's TestMain pins
// every home, stubs the daemon lanes and runs the write guard, so it must
// build in every edition. It lived in a sandbox-tagged file, and the minimal
// edition ran the package with none of that and wrote into the real home.
func TestCmdObserverTestMainIsUntagged(t *testing.T) {
	root := repoRoot(t)
	matches, err := filepath.Glob(filepath.Join(root, "cmd", "observer", "*_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, p := range matches {
		src, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), "\nfunc TestMain(m *testing.M) {") {
			continue
		}
		found++
		for _, line := range strings.SplitN(string(src), "\npackage ", 2)[:1] {
			if strings.Contains(line, "//go:build") {
				t.Errorf("%s holds TestMain behind a build constraint; it must build in every edition", filepath.Base(p))
			}
		}
	}
	if found != 1 {
		t.Fatalf("found %d TestMain functions in cmd/observer, want exactly 1", found)
	}
}
