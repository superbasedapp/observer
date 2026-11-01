package antigravity

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/git"
)

// TestDecodeRootKeepsPOSIXOnWindowsHost pins FU-119: on a Windows host the
// project root of a conversation recorded on Linux or WSL keeps its POSIX
// spelling (it was D:\work\repo, the current drive invented by
// internal/git, which TestParseCLIDB_RecoversTextAndProjectRoot and
// TestLookupCLIIndexEntryDefaultProjectWorkspace caught on the Windows run
// of 2026-10-27). Simulated here, so a POSIX CI host runs it.
func TestDecodeRootKeepsPOSIXOnWindowsHost(t *testing.T) {
	git.SimulateWindowsHostForTest(t)
	for _, c := range []struct{ uri, want string }{
		{"file:///work/repo", "/work/repo"},
		{"file:///home/marmutapp/superbased-observer", "/home/marmutapp/superbased-observer"},
	} {
		if got, _, _ := decodeFileURIToRoot(c.uri); got != c.want {
			t.Errorf("decodeFileURIToRoot(%q) = %q, want %q", c.uri, got, c.want)
		}
	}
}
