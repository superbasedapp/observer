package mcpregister

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/mcp/locate"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// forceMCPCrossmount pins the package's crossmount seam (restored on cleanup)
// so cline-windows detection is deterministic without a real /mnt/c mount.
func forceMCPCrossmount(t *testing.T, homes []crossmount.HomeRoot) {
	t.Helper()
	prev := allHomes
	allHomes = func() []crossmount.HomeRoot { return homes }
	t.Cleanup(func() { allHomes = prev })
}

// mkWinClineHome creates the Windows VS Code globalStorage dir that
// cline-windows detection probes, and returns the Windows USER home.
func mkWinClineHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(locate.ClineLegacySettingsPath(home, crossmount.OSWindows)), 0o755); err != nil {
		t.Fatal(err)
	}
	return home
}

// TestSandboxGate_ClineWindowsSuppressedUnderPinnedHome is the MCP half of the
// 2026-07-31 incident fix (see crossmount.AutoDetectSuppressed). cline-windows
// resolved its write path through crossmount, NOT through HomeDir - so a
// sandboxed caller could write a real Windows VS Code globalStorage. Under a
// pinned home with no WindowsClineHome the target must vanish from Installed()
// and Register must SKIP with no ConfigPath.
func TestSandboxGate_ClineWindowsSuppressedUnderPinnedHome(t *testing.T) {
	winHome := mkWinClineHome(t)
	forceMCPCrossmount(t, []crossmount.HomeRoot{{OS: crossmount.OSWindows, Path: winHome}})

	r, err := NewRegistrar(RegisterOptions{
		BinaryPath: "/bin/observer",
		HomeDir:    t.TempDir(),
		WSLDistro:  "Ubuntu",
		Force:      true, // --force must NOT lift the gate
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.detectWindowsClineSettings(); got != "" {
		t.Errorf("detectWindowsClineSettings() = %q, want \"\" under a pinned home", got)
	}
	for _, tool := range r.Installed() {
		if tool == "cline-windows" {
			t.Errorf("Installed() = %v, must not surface cline-windows under a pinned home", r.Installed())
		}
	}
	res := r.Register("cline-windows")
	if res.Error != nil {
		t.Errorf("Register errored instead of skipping: %v", res.Error)
	}
	if !res.Skipped || res.Added {
		t.Errorf("Register = %+v, want a clean Skipped", res)
	}
	if res.ConfigPath != "" {
		t.Errorf("Register exposed a write path %q - a sandboxed caller must get none", res.ConfigPath)
	}
	if !strings.Contains(res.SkipReason, "2026-07-31") || res.SkipAdvice == "" {
		t.Errorf("skip should name the incident and carry advice, got reason=%q advice=%q", res.SkipReason, res.SkipAdvice)
	}
}

// TestSandboxGate_ClineWindowsProductionUnchanged is the production-parity
// pin: with NO home override (every real `observer init`), crossmount
// detection resolves the Windows globalStorage exactly as before.
func TestSandboxGate_ClineWindowsProductionUnchanged(t *testing.T) {
	winHome := mkWinClineHome(t)
	forceMCPCrossmount(t, []crossmount.HomeRoot{{OS: crossmount.OSWindows, Path: winHome}})

	// HomeDir "" is the production shape: NewRegistrar fills in the real
	// $HOME and homeOverride stays empty, so the gate is inert.
	r, err := NewRegistrar(RegisterOptions{BinaryPath: "/bin/observer"})
	if err != nil {
		t.Fatal(err)
	}
	want := testClineMCPPath(winHome, runtime.GOOS, nil)
	if got := r.detectWindowsClineSettings(); got != want {
		t.Errorf("production detectWindowsClineSettings() = %q, want %q (auto-detect must be unchanged)", got, want)
	}
}

// TestSandboxGate_ClineWindowsUncontainedOverrideSkips is the MCP half of the
// codex NO-SHIP scenario: a sandboxed caller whose WindowsClineHome points at
// an INDEPENDENT root (in the wild: the operator's real Windows home) must be
// refused, not honoured. The first cut of the gate accepted any non-empty
// override, which re-opened the hole it closed.
func TestSandboxGate_ClineWindowsUncontainedOverrideSkips(t *testing.T) {
	forceMCPCrossmount(t, nil) // auto-detect finds nothing
	outside := mkWinClineHome(t)
	r, err := NewRegistrar(RegisterOptions{
		BinaryPath:       "/bin/observer",
		HomeDir:          t.TempDir(), // a DIFFERENT root
		WindowsClineHome: outside,
		WSLDistro:        "Ubuntu",
		Force:            true, // --force must NOT lift containment
	})
	if err != nil {
		t.Fatal(err)
	}
	res := r.Register("cline-windows")
	if res.Error != nil || !res.Skipped || res.ConfigPath != "" || res.Added {
		t.Fatalf("uncontained override must skip cleanly, got %+v", res)
	}
	if !strings.Contains(res.SkipReason, "WindowsClineHome") || !strings.Contains(res.SkipReason, "OUTSIDE") {
		t.Errorf("SkipReason should name the uncontained override, got %q", res.SkipReason)
	}
	if _, err := os.Stat(testClineMCPPath(outside, runtime.GOOS, nil)); err == nil {
		t.Error("settings written into the uncontained override home")
	}
}
