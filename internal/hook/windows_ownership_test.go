package hook

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// forceHookCrossmount pins the hook package's crossmount seams (restored on
// cleanup) so the owned-vs-unowned auto-detect branches of detectWindowsHome
// are deterministic without a real /mnt/c mount or a cmd.exe interop shell.
// owned maps a Windows USER home path to its ownership verdict.
func forceHookCrossmount(t *testing.T, homes []crossmount.HomeRoot, owned map[string]bool) {
	t.Helper()
	prevHomes, prevOwned := allHomes, homeOwnedByCurrentWindowsUser
	allHomes = func() []crossmount.HomeRoot { return homes }
	homeOwnedByCurrentWindowsUser = func(home string) bool { return owned[home] }
	t.Cleanup(func() {
		allHomes = prevHomes
		homeOwnedByCurrentWindowsUser = prevOwned
	})
}

// clearSandboxPin drops a registry's caller-pinned-home marker so the
// crossmount AUTO-DETECT branch of detectWindowsHome runs even though the test
// sandboxed HomeDir. Legitimate only because forceHookCrossmount has already
// replaced the crossmount seams with fakes — nothing here can reach a real
// /mnt/c. Every OTHER caller (including every out-of-package one) keeps the
// sandbox gate; see crossmount.AutoDetectSuppressed (incident 2026-07-31).
func clearSandboxPin(r *Registry) *Registry {
	r.homeOverride = ""
	return r
}

// mkWinConfigHome creates <home>/<subdir> and returns the home dir.
func mkWinConfigHome(t *testing.T, subdir string) string {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, subdir), 0o755); err != nil {
		t.Fatal(err)
	}
	return home
}

// TestDetectWindowsHome_OwnedAutoDetected: a single auto-detected Windows home
// carrying the config dir, PROVEN to belong to the current Windows user, is
// accepted — and surfaces in Installed() (F1: the hook registrar now honours
// the same R1 ownership guard as the proxy-route writer).
func TestDetectWindowsHome_OwnedAutoDetected(t *testing.T) {
	winHome := mkWinConfigHome(t, ".claude")
	forceHookCrossmount(
		t,
		[]crossmount.HomeRoot{{OS: crossmount.OSWindows, Path: winHome}},
		map[string]bool{winHome: true},
	)
	r, err := NewRegistry(Options{BinaryPath: "/bin/observer", HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	r = clearSandboxPin(r) // fakes are installed; exercise the auto-detect branch
	if got := r.detectWindowsClaudeHome(); got != filepath.Join(winHome, ".claude") {
		t.Errorf("detectWindowsClaudeHome() = %q, want owned home", got)
	}
	if !containsString(r.Installed(), "claude-code-windows") {
		t.Errorf("Installed() = %v, want it to include claude-code-windows for the owned home", r.Installed())
	}
}

// TestDetectWindowsHome_UnownedRefused: an auto-detected Windows home whose
// ownership cannot be proven (interop off, or another user's home) is REFUSED —
// detect returns "" and the virtual target does NOT appear in Installed(). This
// is the F1 fix: one `observer init` run must not install hooks into another
// user's .claude just because it is the only one mounted.
func TestDetectWindowsHome_UnownedRefused(t *testing.T) {
	winHome := mkWinConfigHome(t, ".claude")
	forceHookCrossmount(
		t,
		[]crossmount.HomeRoot{{OS: crossmount.OSWindows, Path: winHome}},
		map[string]bool{winHome: false}, // ownership unverifiable / another user
	)
	r, err := NewRegistry(Options{BinaryPath: "/bin/observer", HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	r = clearSandboxPin(r) // fakes are installed; exercise the auto-detect branch
	if got := r.detectWindowsClaudeHome(); got != "" {
		t.Errorf("detectWindowsClaudeHome() = %q, want empty (unowned refused)", got)
	}
	if containsString(r.Installed(), "claude-code-windows") {
		t.Errorf("Installed() = %v, must NOT include claude-code-windows for an unowned home", r.Installed())
	}
}

// TestDetectWindowsHome_AmbiguousRefused: two owned candidates (a shape the
// ownership match makes near-impossible, but guarded anyway) refuse to
// auto-pick — detect returns "" rather than guessing, mirroring the
// proxy-route writer.
func TestDetectWindowsHome_AmbiguousRefused(t *testing.T) {
	homeA := mkWinConfigHome(t, ".cursor")
	homeB := mkWinConfigHome(t, ".cursor")
	forceHookCrossmount(
		t,
		[]crossmount.HomeRoot{
			{OS: crossmount.OSWindows, Path: homeA},
			{OS: crossmount.OSWindows, Path: homeB},
		},
		map[string]bool{homeA: true, homeB: true},
	)
	r, err := NewRegistry(Options{BinaryPath: "/bin/observer", HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	r = clearSandboxPin(r) // fakes are installed; exercise the auto-detect branch
	if got := r.detectWindowsCursorHome(); got != "" {
		t.Errorf("detectWindowsCursorHome() = %q, want empty (ambiguous refused)", got)
	}
}

// TestDetectWindowsHome_OverrideWinsOverOwnership: an explicit override is
// authoritative over the R1 OWNERSHIP check — the operator named the home, so
// proving it belongs to the current Windows user is moot. (It is NOT
// authoritative over the sandbox-containment gate; that is
// TestSandboxGate_*.) Two shapes are pinned:
//
//   - production (HomeDir empty, bare override — `observer init
//     --windows-claude-home=/mnt/c/Users/<u>`): the override wins outright,
//     byte-identical to pre-gate behaviour.
//   - sandboxed (HomeDir pinned): the override wins too, as long as it lives
//     under the pinned home.
func TestDetectWindowsHome_OverrideWinsOverOwnership(t *testing.T) {
	forceHookCrossmount(t, nil, map[string]bool{}) // nothing owned

	// Production shape: no HomeDir override at all, bare Windows override.
	bare := t.TempDir()
	prod, err := NewRegistry(Options{BinaryPath: "/bin/observer", WindowsClaudeHome: bare})
	if err != nil {
		t.Fatal(err)
	}
	if got := prod.detectWindowsClaudeHome(); got != filepath.Join(bare, ".claude") {
		t.Errorf("production bare override: detectWindowsClaudeHome() = %q, want %q", got, filepath.Join(bare, ".claude"))
	}
	if !containsString(prod.Installed(), "claude-code-windows") {
		t.Errorf("production bare override: Installed() = %v, want claude-code-windows", prod.Installed())
	}

	// Sandboxed shape: the override lives inside the pinned home.
	sandbox := t.TempDir()
	override := filepath.Join(sandbox, "winhome")
	if err := os.MkdirAll(override, 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistry(Options{
		BinaryPath:        "/bin/observer",
		HomeDir:           sandbox,
		WindowsClaudeHome: override,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.detectWindowsClaudeHome(); got != filepath.Join(override, ".claude") {
		t.Errorf("detectWindowsClaudeHome() = %q, want the contained override home", got)
	}
	if !containsString(r.Installed(), "claude-code-windows") {
		t.Errorf("Installed() = %v, want claude-code-windows for the contained override", r.Installed())
	}
}

// TestDetectWindowsHome_NewVendorsShareTheSameGuardRails pins that the
// six Part B item 1/2 cross-OS bridge targets added alongside
// register*Windows (gemini-cli, qwen-code, droid, qoder, poolside,
// command-code) resolve through the SAME detectWindowsHome guard rails
// as claude-code/cursor/codex — table-driven rather than duplicating
// six near-identical copies of TestDetectWindowsHome_OwnedAutoDetected /
// TestDetectWindowsHome_UnownedRefused.
func TestDetectWindowsHome_NewVendorsShareTheSameGuardRails(t *testing.T) {
	cases := []struct {
		name   string
		subdir string
		detect func(*Registry) string
	}{
		{"gemini-cli", ".gemini", (*Registry).detectWindowsGeminiHome},
		{"qwen-code", ".qwen", (*Registry).detectWindowsQwenHome},
		{"droid", ".factory", (*Registry).detectWindowsFactoryHome},
		{"qoder", ".qoder", (*Registry).detectWindowsQoderHome},
		{"poolside", filepath.Join(".config", "poolside"), (*Registry).detectWindowsPoolsideHome},
		{"command-code", ".commandcode", (*Registry).detectWindowsCommandCodeHome},
	}
	for _, c := range cases {
		t.Run(c.name+"/owned", func(t *testing.T) {
			winHome := mkWinConfigHome(t, c.subdir)
			forceHookCrossmount(t, []crossmount.HomeRoot{{OS: crossmount.OSWindows, Path: winHome}}, map[string]bool{winHome: true})
			r, err := NewRegistry(Options{BinaryPath: "/bin/observer", HomeDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			r = clearSandboxPin(r)
			if got := c.detect(r); got != filepath.Join(winHome, c.subdir) {
				t.Errorf("detect = %q, want owned home %q", got, filepath.Join(winHome, c.subdir))
			}
			if !containsString(r.Installed(), c.name+"-windows") {
				t.Errorf("Installed() = %v, want %s-windows for the owned home", r.Installed(), c.name)
			}
		})
		t.Run(c.name+"/unowned", func(t *testing.T) {
			winHome := mkWinConfigHome(t, c.subdir)
			forceHookCrossmount(t, []crossmount.HomeRoot{{OS: crossmount.OSWindows, Path: winHome}}, map[string]bool{winHome: false})
			r, err := NewRegistry(Options{BinaryPath: "/bin/observer", HomeDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			r = clearSandboxPin(r)
			if got := c.detect(r); got != "" {
				t.Errorf("detect = %q, want empty (unowned refused)", got)
			}
			if containsString(r.Installed(), c.name+"-windows") {
				t.Errorf("Installed() = %v, must NOT include %s-windows for an unowned home", r.Installed(), c.name)
			}
		})
	}
}
