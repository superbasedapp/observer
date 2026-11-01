package clinecli

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// TestIsForeignMountPath pins the helper's contract: only paths
// under cross-mount-detected non-native homes match. Tests inject a
// fake AllHomes returning one native + one foreign home so the
// assertion runs identically on any host.
func TestIsForeignMountPath(t *testing.T) {
	orig := allHomesFunc
	t.Cleanup(func() { allHomesFunc = orig })
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{
			{Path: "/home/me", OS: crossmount.OSLinux, Origin: "native"},
			{Path: "/mnt/c/Users/marmu", OS: crossmount.OSWindows, Origin: "wsl-mnt:marmu"},
		}
	}
	cases := []struct {
		path string
		want bool
	}{
		{"/home/me/.cline/data/db/sessions.db", false},
		{"/mnt/c/Users/marmu/.cline/data/db/sessions.db", true},
		{"/mnt/c/Users/marmu/.cline/data/db/sessions.db-wal", true},
		{"/mnt/c/Users/marmu/.cline/data/db/sessions.db-shm", true},
		{"/tmp/random", false},
		{"/mnt/c/Users/other/.cline/data/db/sessions.db", false}, // wrong user
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if got := isForeignMountPath(tc.path); got != tc.want {
				t.Errorf("isForeignMountPath(%q) = %v; want %v", tc.path, got, tc.want)
			}
		})
	}
}

// TestStageMirrorIfForeign_NativePassThrough pins the no-op fast
// path. Native sessions.db opens directly — no copy, no cache dir
// touched. Critical: every scan goes through this helper; an
// accidental always-copy would burn I/O on every native poll.
func TestStageMirrorIfForeign_NativePassThrough(t *testing.T) {
	orig := allHomesFunc
	t.Cleanup(func() { allHomesFunc = orig })
	allHomesFunc = func() []crossmount.HomeRoot {
		return []crossmount.HomeRoot{
			{Path: "/home/me", OS: crossmount.OSLinux, Origin: "native"},
		}
	}
	got, err := stageMirrorIfForeign("/home/me/.cline/data/db/sessions.db")
	if err != nil {
		t.Fatalf("stageMirrorIfForeign: %v", err)
	}
	if got != "/home/me/.cline/data/db/sessions.db" {
		t.Errorf("native path got remapped to %q; want passthrough", got)
	}
}
