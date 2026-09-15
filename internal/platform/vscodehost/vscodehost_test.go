package vscodehost

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

func TestUserDir(t *testing.T) {
	code := Product{Dir: "Code", Host: "vscode"}
	cursor := Product{Dir: "Cursor", Host: "cursor"}
	remoteVSCode := Product{Dir: ".vscode-server", Host: "vscode-remote", Remote: true}
	remoteCursor := Product{Dir: ".cursor-server", Host: "cursor-remote", Remote: true}

	cases := []struct {
		name string
		h    crossmount.HomeRoot
		p    Product
		want string
	}{
		{
			name: "windows non-native",
			h:    crossmount.HomeRoot{Path: `C:\Users\auzy_`, OS: crossmount.OSWindows, Origin: "wsl-mnt:auzy_"},
			p:    code,
			want: filepath.Join(`C:\Users\auzy_`, "AppData", "Roaming", "Code", "User"),
		},
		{
			name: "darwin",
			h:    crossmount.HomeRoot{Path: "/Users/auzy", OS: crossmount.OSDarwin, Origin: "native"},
			p:    cursor,
			want: filepath.Join("/Users/auzy", "Library", "Application Support", "Cursor", "User"),
		},
		{
			name: "linux",
			h:    crossmount.HomeRoot{Path: "/home/auzy", OS: crossmount.OSLinux, Origin: "native"},
			p:    code,
			want: filepath.Join("/home/auzy", ".config", "Code", "User"),
		},
		{
			name: "unknown os",
			h:    crossmount.HomeRoot{Path: "/x", OS: "plan9", Origin: "native"},
			p:    code,
			want: "",
		},
		{
			name: "remote vscode-server on linux home",
			h:    crossmount.HomeRoot{Path: "/home/auzy", OS: crossmount.OSLinux, Origin: "native"},
			p:    remoteVSCode,
			want: filepath.Join("/home/auzy", ".vscode-server", "data", "User"),
		},
		{
			name: "remote cursor-server on darwin home",
			h:    crossmount.HomeRoot{Path: "/Users/auzy", OS: crossmount.OSDarwin, Origin: "native"},
			p:    remoteCursor,
			want: filepath.Join("/Users/auzy", ".cursor-server", "data", "User"),
		},
		{
			name: "remote on windows home",
			h:    crossmount.HomeRoot{Path: `C:\Users\auzy_`, OS: crossmount.OSWindows, Origin: "native"},
			p:    remoteVSCode,
			want: filepath.Join(`C:\Users\auzy_`, ".vscode-server", "data", "User"),
		},
		{
			name: "remote unknown os",
			h:    crossmount.HomeRoot{Path: "/x", OS: "plan9", Origin: "native"},
			p:    remoteVSCode,
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := UserDir(tc.h, tc.p)
			if got != tc.want {
				t.Errorf("UserDir(%+v, %+v) = %q, want %q", tc.h, tc.p, got, tc.want)
			}
		})
	}
}

// TestUserDir_WindowsNativeAppDataOverride pins the native-home APPDATA
// override every predecessor helper (cline/kilocode/cursor) applied: when
// the running process is itself on Windows and h.Origin is "native", a set
// APPDATA wins over the derived AppData/Roaming path. Guarded to Windows
// since runtime.GOOS is part of the branch condition.
func TestUserDir_WindowsNativeAppDataOverride(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("APPDATA native override only branches on windows")
	}
	t.Setenv("APPDATA", `D:\CustomRoaming`)

	h := crossmount.HomeRoot{Path: `C:\Users\auzy_`, OS: crossmount.OSWindows, Origin: "native"}
	p := Product{Dir: "Code", Host: "vscode"}

	got := UserDir(h, p)
	want := filepath.Join(`D:\CustomRoaming`, "Code", "User")
	if got != want {
		t.Errorf("UserDir with APPDATA override = %q, want %q", got, want)
	}
}

// TestUserDir_WindowsNativeAppDataUnset pins the fallback: native origin +
// windows GOOS, but APPDATA unset, still derives AppData/Roaming under
// h.Path rather than returning "".
func TestUserDir_WindowsNativeAppDataUnset(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("APPDATA native override only branches on windows")
	}
	t.Setenv("APPDATA", "")

	h := crossmount.HomeRoot{Path: `C:\Users\auzy_`, OS: crossmount.OSWindows, Origin: "native"}
	p := Product{Dir: "Code", Host: "vscode"}

	got := UserDir(h, p)
	want := filepath.Join(`C:\Users\auzy_`, "AppData", "Roaming", "Code", "User")
	if got != want {
		t.Errorf("UserDir with APPDATA unset = %q, want %q", got, want)
	}
}

func TestProducts(t *testing.T) {
	got := Products()
	if len(got) != len(products) {
		t.Fatalf("Products() len = %d, want %d", len(got), len(products))
	}
	// Mutating the returned slice must not affect the package table.
	got[0].Dir = "mutated"
	if products[0].Dir == "mutated" {
		t.Fatalf("Products() leaked the internal slice — mutation affected package state")
	}
	wantOrder := []string{"Code", "Code - Insiders", "VSCodium", "Cursor", "Windsurf", "Kiro", "Qoder", "Trae", ".vscode-server", ".cursor-server"}
	got = Products()
	for i, w := range wantOrder {
		if got[i].Dir != w {
			t.Errorf("Products()[%d].Dir = %q, want %q", i, got[i].Dir, w)
		}
	}
	// Desktop products first, remote ones last.
	for i, p := range got {
		wantRemote := i >= len(got)-2
		if p.Remote != wantRemote {
			t.Errorf("Products()[%d] (%s) Remote = %v, want %v", i, p.Dir, p.Remote, wantRemote)
		}
	}
}

func TestUserDirs(t *testing.T) {
	h := crossmount.HomeRoot{Path: "/home/auzy", OS: crossmount.OSLinux, Origin: "native"}
	refs := UserDirs(h)
	if len(refs) != len(products) {
		t.Fatalf("UserDirs() len = %d, want %d (linux resolves every product)", len(refs), len(products))
	}
	for i, r := range refs {
		if r.Product.Dir != products[i].Dir {
			t.Errorf("UserDirs()[%d].Product.Dir = %q, want %q (order must follow Products())", i, r.Product.Dir, products[i].Dir)
		}
		if r.Path == "" {
			t.Errorf("UserDirs()[%d].Path is empty for a known OS", i)
		}
	}

	unknown := crossmount.HomeRoot{Path: "/x", OS: "plan9", Origin: "native"}
	if refs := UserDirs(unknown); len(refs) != 0 {
		t.Errorf("UserDirs() for unknown OS = %d refs, want 0", len(refs))
	}
}

func TestGlobalStorageDirs(t *testing.T) {
	h := crossmount.HomeRoot{Path: "/home/auzy", OS: crossmount.OSLinux, Origin: "native"}
	base := UserDirs(h)
	got := GlobalStorageDirs(h)
	if len(got) != len(base) {
		t.Fatalf("GlobalStorageDirs() len = %d, want %d", len(got), len(base))
	}
	for i, r := range got {
		want := filepath.Join(base[i].Path, "globalStorage")
		if r.Path != want {
			t.Errorf("GlobalStorageDirs()[%d].Path = %q, want %q", i, r.Path, want)
		}
		if r.Product.Dir != base[i].Product.Dir {
			t.Errorf("GlobalStorageDirs()[%d].Product = %+v, want %+v", i, r.Product, base[i].Product)
		}
	}
}

func TestWorkspaceStorageDirs(t *testing.T) {
	h := crossmount.HomeRoot{Path: "/home/auzy", OS: crossmount.OSLinux, Origin: "native"}
	base := UserDirs(h)
	got := WorkspaceStorageDirs(h)
	if len(got) != len(base) {
		t.Fatalf("WorkspaceStorageDirs() len = %d, want %d", len(got), len(base))
	}
	for i, r := range got {
		want := filepath.Join(base[i].Path, "workspaceStorage")
		if r.Path != want {
			t.Errorf("WorkspaceStorageDirs()[%d].Path = %q, want %q", i, r.Path, want)
		}
	}
}

func TestProductForPath(t *testing.T) {
	cases := []struct {
		name      string
		path      string
		wantDir   string
		wantFound bool
	}{
		{
			name:      "windows code globalStorage",
			path:      `C:\Users\auzy_\AppData\Roaming\Code\User\globalStorage\saoudrizwan.claude-dev`,
			wantDir:   "Code",
			wantFound: true,
		},
		{
			name:      "macOS cursor workspaceStorage",
			path:      "/Users/auzy/Library/Application Support/Cursor/User/workspaceStorage/abc123",
			wantDir:   "Cursor",
			wantFound: true,
		},
		{
			name:      "linux code globalStorage",
			path:      "/home/auzy/.config/Code/User/globalStorage/github.copilot-chat",
			wantDir:   "Code",
			wantFound: true,
		},
		{
			name:      "insiders is not code",
			path:      "/home/auzy/.config/Code - Insiders/User/globalStorage/foo",
			wantDir:   "Code - Insiders",
			wantFound: true,
		},
		{
			name:      "case insensitive segment match",
			path:      `c:\users\auzy_\appdata\roaming\code\user\globalStorage\foo`,
			wantDir:   "Code",
			wantFound: true,
		},
		{
			name:      "remote vscode-server",
			path:      "/home/auzy/.vscode-server/data/User/globalStorage/foo",
			wantDir:   ".vscode-server",
			wantFound: true,
		},
		{
			name:      "remote cursor-server backslash path",
			path:      `\home\auzy\.cursor-server\data\User\globalStorage\foo`,
			wantDir:   ".cursor-server",
			wantFound: true,
		},
		{
			name:      "non-matching path",
			path:      "/home/auzy/.local/share/kilo/kilo.db",
			wantFound: false,
		},
		{
			name:      "code segment without trailing User is not a match",
			path:      "/home/auzy/.config/Code/extensions/foo",
			wantFound: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, found := ProductForPath(tc.path)
			if found != tc.wantFound {
				t.Fatalf("ProductForPath(%q) found = %v, want %v", tc.path, found, tc.wantFound)
			}
			if found && got.Dir != tc.wantDir {
				t.Errorf("ProductForPath(%q).Dir = %q, want %q", tc.path, got.Dir, tc.wantDir)
			}
		})
	}
}
