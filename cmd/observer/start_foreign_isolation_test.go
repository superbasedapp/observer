package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// TestAutoRegisterHooks_NeverReachesForeignHome is the regression for
// incident 2026-10-02: TestAutoRegisterHooks_PromptLaneOnlyGate faked
// HOME/USERPROFILE and called autoRegisterHooks, whose unpinned
// hook.NewRegistry walked crossmount's fixed /mnt/c/Users root, found the
// operator's REAL Windows-side .claude, and rewrote its 22 hook commands to a
// throwaway test binary.
//
// The fixture reproduces that shape inside t.TempDir(): a detectable,
// ownership-proven foreign home (NTUSER.DAT marker, .claude/, WindowsUser
// pinned to its leaf) sits at the root the default detector scans, HOME is a
// separate temp dir, and WSL_DISTRO_NAME is set. With the guard every test
// binary carries, autoRegisterHooks must write nothing there and every path
// it reports must stay inside the sandbox. The control subtest lifts
// discovery for the staged root ONLY and shows the same fixture IS wired, so
// the guard — not a malformed fixture — is what protects the real home. Not
// parallel: it stages process-wide crossmount state and sets env.
func TestAutoRegisterHooks_NeverReachesForeignHome(t *testing.T) {
	requireComponents(t, "integration.hooks")
	requireActiveAdapters(t, "claude-code")
	requireAdapter(t, "claude-code")
	if runtime.GOOS != "linux" {
		t.Skip("the -windows bridge targets only exist for a Linux (WSL) daemon")
	}
	const (
		winUser  = "operator"
		sentinel = `{"hooks":{},"sentinel":"operator-owned"}` + "\n"
	)
	setup := func(t *testing.T, discover bool) (sandbox, home, foreignSettings string) {
		t.Helper()
		sandbox = t.TempDir()
		home = filepath.Join(sandbox, "home")
		usersRoot := filepath.Join(sandbox, "mnt", "c", "Users")
		winHome := filepath.Join(usersRoot, winUser)
		for _, d := range []string{filepath.Join(home, ".claude"), filepath.Join(winHome, ".claude")} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(winHome, "NTUSER.DAT"), []byte("hive"), 0o600); err != nil {
			t.Fatal(err)
		}
		foreignSettings = filepath.Join(winHome, ".claude", "settings.json")
		if err := os.WriteFile(foreignSettings, []byte(sentinel), 0o600); err != nil {
			t.Fatal(err)
		}
		// Every profile root and tool home stays in the throwaway home
		// (surface-gap S-10, FU-4).
		pinToolHomesAt(t, home)
		t.Setenv("WSL_DISTRO_NAME", "TestDistro")
		crossmount.StageForeignLayoutForTest(t, crossmount.ForeignLayoutForTest{
			Root: usersRoot, WindowsUser: winUser, Discover: discover,
		})
		return sandbox, home, foreignSettings
	}

	t.Run("guarded: the foreign home is never touched", func(t *testing.T) {
		sandbox, home, foreignSettings := setup(t, false)
		var stdout, stderr bytes.Buffer
		autoRegisterHooks(&stdout, &stderr, "", false)

		got, err := os.ReadFile(foreignSettings)
		if err != nil {
			t.Fatalf("read foreign settings: %v", err)
		}
		if string(got) != sentinel {
			t.Errorf("foreign settings.json was rewritten:\n%s", got)
		}
		if strings.Contains(stdout.String()+stderr.String(), "claude-code-windows") {
			t.Errorf("a claude-code-windows target surfaced under the guard\nstdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
		}
		if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); err != nil {
			t.Errorf("native ~/.claude/settings.json was NOT written (the test must still exercise a live registration): %v", err)
		}
		assertInstalledPathsUnder(t, stdout.String(), sandbox)
	})

	t.Run("control: discovery allowed for the staged root wires the bridge there", func(t *testing.T) {
		sandbox, _, foreignSettings := setup(t, true)
		var stdout, stderr bytes.Buffer
		autoRegisterHooks(&stdout, &stderr, "", false)

		if !strings.Contains(stdout.String(), "auto-register claude-code-windows: installed") {
			t.Fatalf("control did not register claude-code-windows - the fixture is not detectable, so the guarded subtest proves nothing\nstdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
		}
		got, err := os.ReadFile(foreignSettings)
		if err != nil {
			t.Fatalf("read foreign settings: %v", err)
		}
		if !strings.Contains(string(got), "wsl.exe -d TestDistro") {
			t.Errorf("staged foreign settings.json lacks the wsl.exe bridge:\n%s", got)
		}
		assertInstalledPathsUnder(t, stdout.String(), sandbox)
	})
}

// assertInstalledPathsUnder checks every "installed N hook(s) at <path>" line
// autoRegisterHooks printed names a path inside sandbox.
func assertInstalledPathsUnder(t *testing.T, stdout, sandbox string) {
	t.Helper()
	const marker = " hook(s) at "
	for _, line := range strings.Split(stdout, "\n") {
		i := strings.Index(line, marker)
		if i < 0 {
			continue
		}
		p := strings.TrimSpace(line[i+len(marker):])
		if !crossmount.PathUnder(sandbox, p) {
			t.Errorf("autoRegisterHooks wrote %q, outside the test sandbox %q", p, sandbox)
		}
	}
}
