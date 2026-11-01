package vtcode

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

func TestStateRootsForHome(t *testing.T) {
	tests := []struct {
		name string
		home crossmount.HomeRoot
		want string // slash form suffix; "" = no root
	}{
		{"linux XDG state", crossmount.HomeRoot{Path: filepath.Join("h", "u"), OS: crossmount.OSLinux}, "h/u/.local/state/vtcode/sessions"},
		{"windows roaming", crossmount.HomeRoot{Path: filepath.Join("h", "u"), OS: crossmount.OSWindows}, "h/u/AppData/Roaming/vinhnx/vtcode/state/sessions"},
		{"macOS ungrounded", crossmount.HomeRoot{Path: filepath.Join("h", "u"), OS: crossmount.OSDarwin}, ""},
		{"empty home", crossmount.HomeRoot{OS: crossmount.OSLinux}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := stateRootsForHome(tc.home)
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("got %v, want none", got)
				}
				return
			}
			if len(got) != 1 || filepath.ToSlash(got[0]) != tc.want {
				t.Fatalf("got %v, want %q", got, tc.want)
			}
		})
	}
}

func TestDefaultStateRootsXDGOverride(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("XDG_STATE_HOME is honoured only on a native Linux host")
	}
	x := t.TempDir()
	t.Setenv("XDG_STATE_HOME", x)
	roots := defaultStateRoots()
	if len(roots) == 0 || roots[0] != filepath.Join(x, "vtcode", "sessions") {
		t.Fatalf("defaultStateRoots() = %v, want the XDG override first", roots)
	}
}

func TestDefaultStateRootsShape(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range defaultStateRoots() {
		if r == "" || seen[r] {
			t.Fatalf("empty or duplicate root %q", r)
		}
		seen[r] = true
		if !strings.HasSuffix(filepath.ToSlash(r), "/vtcode/sessions") && !strings.HasSuffix(filepath.ToSlash(r), "/vtcode/state/sessions") {
			t.Errorf("root %q is not a vtcode archive dir", r)
		}
		if isWorkspaceSessionsRoot(r) {
			t.Errorf("archive root %q classified as a workspace store", r)
		}
	}
}

func TestWorkspaceDiscoveryFromArchive(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "state", "sessions")
	ws := filepath.Join(dir, "proj")
	writeArchive(t, filepath.Join(archive, "session-proj-20261021T000000Z_1-1.json"), ws, "m", "")
	writeArchive(t, filepath.Join(archive, "session-proj-20261021T000001Z_2-2.json"), ws, "m", "") // same workspace
	writeFile(t, filepath.Join(archive, "notes.json"), "{}")
	writeFile(t, filepath.Join(archive, "session-broken.json"), "{")

	got := workspaceSessionDirs(archive)
	want := filepath.Join(ws, ".vtcode", "sessions")
	if len(got) != 1 || got[0] != want {
		t.Fatalf("workspaceSessionDirs = %v, want [%s]", got, want)
	}
	if !isWorkspaceSessionsRoot(got[0]) {
		t.Errorf("%q not classified as a workspace store", got[0])
	}
	if workspaceSessionDirs(filepath.Join(dir, "missing")) != nil {
		t.Error("missing archive dir should yield nil")
	}
}

func TestResolveWorkspacePath(t *testing.T) {
	tests := []struct {
		name, statePath, ws, want string
		skip                      bool
	}{
		{name: "empty", statePath: "/x/s.json", ws: "  ", want: ""},
		{
			name:      "posix workspace read through the WSL UNC share",
			statePath: `\\wsl.localhost\Ubuntu\home\user\.local\state\vtcode\sessions\s.json`,
			ws:        "/home/user/demo-wsl",
			want:      `\\wsl.localhost\Ubuntu\home\user\demo-wsl`,
		},
		{
			name:      "legacy wsl$ share, forward slashes",
			statePath: `//wsl$/Debian/home/u/.local/state/vtcode/sessions/s.json`,
			ws:        "/srv/p",
			want:      `//wsl$/Debian/srv/p`,
		},
		{
			name:      "windows workspace read from WSL",
			statePath: "/mnt/c/Users/user/AppData/Roaming/vinhnx/vtcode/state/sessions/s.json",
			ws:        `C:\Users\user\demo-win`,
			want:      "/mnt/c/Users/user/demo-win",
			skip:      runtime.GOOS == "windows",
		},
		{
			name:      "native posix workspace",
			statePath: "/home/user/.local/state/vtcode/sessions/s.json",
			ws:        "/home/user/p",
			want:      "/home/user/p",
			skip:      runtime.GOOS == "windows",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skip {
				t.Skip("drive-letter translation and POSIX cleaning are Linux/WSL behaviour")
			}
			got := resolveWorkspacePath(tc.statePath, tc.ws)
			if strings.HasPrefix(tc.want, "//") {
				got = filepath.ToSlash(got)
				// The UNC prefix is always rendered with backslashes.
				got = strings.ReplaceAll(got, `\`, "/")
			}
			if got != tc.want {
				t.Fatalf("resolveWorkspacePath(%q, %q) = %q, want %q", tc.statePath, tc.ws, got, tc.want)
			}
		})
	}
}

func TestWSLUNCPrefix(t *testing.T) {
	tests := []struct{ in, want string }{
		{`\\wsl.localhost\Ubuntu\home\u`, `\\wsl.localhost\Ubuntu`},
		{`\\WSL$\Debian\x`, `\\WSL$\Debian`},
		{`//wsl.localhost/Ubuntu/home`, `\\wsl.localhost\Ubuntu`},
		{`\\wsl.localhost\`, ""},
		{`C:\Users\u`, ""},
		{"/home/u", ""},
	}
	for _, tc := range tests {
		if got := wslUNCPrefix(tc.in); got != tc.want {
			t.Errorf("wslUNCPrefix(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
