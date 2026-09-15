package cowork

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// withFakeHomes swaps the crossmount.AllHomes seam for the duration of
// a test so root discovery is assertable without depending on the
// host's filesystem layout.
func withFakeHomes(t *testing.T, homes ...crossmount.HomeRoot) {
	t.Helper()
	orig := allHomesFunc
	t.Cleanup(func() { allHomesFunc = orig })
	allHomesFunc = func() []crossmount.HomeRoot { return homes }
}

// TestWatchPaths_MSIXReparseCollapsesToOneRoot is the IDE-01
// regression pin. On a Windows MSIX Claude Desktop install
// `%APPDATA%\Claude` is a reparse point onto
// `…\Packages\Claude_<hash>\LocalCache\Roaming\Claude`, so
// candidateRoots legitimately returns TWO spellings of ONE directory.
// WatchPaths must collapse them — otherwise the watcher walks the tree
// twice and every audit.jsonl is ingested under two distinct
// source_file values (an exact 2x action-row inflation).
//
// A directory symlink stands in for the reparse point; os.Symlink
// needs SeCreateSymbolicLinkPrivilege on Windows, so the test skips
// when the host refuses.
func TestWatchPaths_MSIXReparseCollapsesToOneRoot(t *testing.T) {
	home := t.TempDir()

	msix := filepath.Join(home, "AppData", "Local", "Packages", "Claude_abc",
		"LocalCache", "Roaming", "Claude", "local-agent-mode-sessions")
	if err := os.MkdirAll(msix, 0o755); err != nil {
		t.Fatalf("mkdir msix: %v", err)
	}

	// %APPDATA%\Claude is the reparse point; link the whole `Claude`
	// directory the way the MSIX redirect does, not just the leaf.
	roamingParent := filepath.Join(home, "AppData", "Roaming")
	if err := os.MkdirAll(roamingParent, 0o755); err != nil {
		t.Fatalf("mkdir roaming: %v", err)
	}
	msixClaude := filepath.Dir(msix) // …\LocalCache\Roaming\Claude
	if err := os.Symlink(msixClaude, filepath.Join(roamingParent, "Claude")); err != nil {
		t.Skipf("os.Symlink unsupported on this host (privilege?): %v", err)
	}

	withFakeHomes(t, crossmount.HomeRoot{OS: crossmount.OSWindows, Path: home})

	got := New().WatchPaths()
	if len(got) != 1 {
		t.Fatalf("WatchPaths()=%v want 1 entry (MSIX reparse alias must collapse)", got)
	}
	if got[0] != msix {
		t.Fatalf("WatchPaths()[0]=%q want %q (first candidate wins)", got[0], msix)
	}
}

// TestWatchPaths_KeepsDistinctAndMissingRoots pins the other half:
// dedup must NOT swallow a root that is merely absent. A non-MSIX
// home yields only the Roaming spelling, which does not exist here and
// is still returned (Invariant #48 — the watcher drops missing roots,
// the adapter does not).
func TestWatchPaths_KeepsDistinctAndMissingRoots(t *testing.T) {
	homeA := t.TempDir()
	homeB := t.TempDir()

	msix := filepath.Join(homeA, "AppData", "Local", "Packages", "Claude_abc",
		"LocalCache", "Roaming", "Claude", "local-agent-mode-sessions")
	if err := os.MkdirAll(msix, 0o755); err != nil {
		t.Fatalf("mkdir msix: %v", err)
	}

	withFakeHomes(t,
		crossmount.HomeRoot{OS: crossmount.OSWindows, Path: homeA},
		crossmount.HomeRoot{OS: crossmount.OSWindows, Path: homeB},
	)

	want := []string{
		msix,
		filepath.Join(homeA, "AppData", "Roaming", "Claude", "local-agent-mode-sessions"),
		filepath.Join(homeB, "AppData", "Roaming", "Claude", "local-agent-mode-sessions"),
	}
	got := New().WatchPaths()
	if len(got) != len(want) {
		t.Fatalf("WatchPaths()=%v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("WatchPaths()[%d]=%q want %q", i, got[i], want[i])
		}
	}
}

// TestWatchPaths_DropsDuplicateHomes pins that two crossmount homes
// resolving to the SAME directory (a native home also enumerated as a
// cross-mount home) contribute one root, not two.
func TestWatchPaths_DropsDuplicateHomes(t *testing.T) {
	home := t.TempDir()
	sessions := filepath.Join(home, "AppData", "Roaming", "Claude", "local-agent-mode-sessions")
	if err := os.MkdirAll(sessions, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	withFakeHomes(t,
		crossmount.HomeRoot{OS: crossmount.OSWindows, Path: home},
		crossmount.HomeRoot{OS: crossmount.OSWindows, Path: home + string(filepath.Separator)},
	)

	got := New().WatchPaths()
	if len(got) != 1 || got[0] != sessions {
		t.Fatalf("WatchPaths()=%v want [%q]", got, sessions)
	}
}
