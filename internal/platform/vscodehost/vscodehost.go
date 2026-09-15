package vscodehost

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// Product describes one VS Code-family editor whose user-data layout this
// package knows how to locate.
type Product struct {
	// Dir is the product's user-data directory name as VS Code itself
	// names it on disk — e.g. "Code", "Code - Insiders", "VSCodium",
	// "Cursor", "Windsurf", "Kiro", "Qoder", "Trae". For a Remote
	// product, Dir instead holds the server directory name under the
	// home root — e.g. ".vscode-server", ".cursor-server".
	Dir string
	// Host is the lowercase surface-host token this product stamps
	// alongside models.SurfaceIDE — e.g. "vscode", "vscode-insiders",
	// "vscodium", "cursor", "windsurf", "kiro", "qoder", "trae",
	// "vscode-remote", "cursor-remote".
	Host string
	// Remote marks a server-side layout (VS Code Server / Cursor
	// Server) reached over SSH, WSL, or a dev container, as opposed to
	// a desktop install.
	Remote bool
}

// products is the ordered table of every VS Code-family product this
// package enumerates: desktop products first (in the order an operator is
// most likely to have them installed), then remote server layouts.
var products = []Product{
	{Dir: "Code", Host: "vscode"},
	{Dir: "Code - Insiders", Host: "vscode-insiders"},
	{Dir: "VSCodium", Host: "vscodium"},
	{Dir: "Cursor", Host: "cursor"},
	{Dir: "Windsurf", Host: "windsurf"},
	{Dir: "Kiro", Host: "kiro"},
	{Dir: "Qoder", Host: "qoder"},
	{Dir: "Trae", Host: "trae"},
	{Dir: ".vscode-server", Host: "vscode-remote", Remote: true},
	{Dir: ".cursor-server", Host: "cursor-remote", Remote: true},
}

// Products returns the ordered table of every VS Code-family product this
// package knows about. Callers get a fresh copy; mutating the result never
// affects the package's own table.
func Products() []Product {
	out := make([]Product, len(products))
	copy(out, products)
	return out
}

// UserDir returns product p's "<...>/User" directory under home root h,
// following the same per-OS convention every hand-rolled predecessor used
// (internal/adapter/cline, copilot, kilocode, cursor):
//
//   - windows: <home>/AppData/Roaming/<Dir>/User, except when h.Origin is
//     "native" and the process itself is running on Windows, in which case
//     %APPDATA%/<Dir>/User is preferred when APPDATA is set (the roaming
//     profile can live off the default drive).
//   - darwin:  <home>/Library/Application Support/<Dir>/User
//   - linux:   <home>/.config/<Dir>/User
//
// A Remote product (p.Remote) ignores that ladder and always resolves to
// <home>/<Dir>/data/User, since a VS Code Server / Cursor Server layout is
// the same POSIX-shaped subpath regardless of the client desktop's OS.
//
// UserDir returns "" for a home whose OS is not one of
// crossmount.OSWindows/OSDarwin/OSLinux.
func UserDir(h crossmount.HomeRoot, p Product) string {
	if p.Remote {
		switch h.OS {
		case crossmount.OSWindows, crossmount.OSDarwin, crossmount.OSLinux:
			return filepath.Join(h.Path, p.Dir, "data", "User")
		default:
			return ""
		}
	}

	switch h.OS {
	case crossmount.OSWindows:
		if h.Origin == "native" && runtime.GOOS == "windows" {
			if appData := os.Getenv("APPDATA"); appData != "" {
				return filepath.Join(appData, p.Dir, "User")
			}
		}
		return filepath.Join(h.Path, "AppData", "Roaming", p.Dir, "User")
	case crossmount.OSDarwin:
		return filepath.Join(h.Path, "Library", "Application Support", p.Dir, "User")
	case crossmount.OSLinux:
		return filepath.Join(h.Path, ".config", p.Dir, "User")
	default:
		return ""
	}
}

// UserDirRef pairs a resolved directory path with the Product it was
// resolved for, so a caller can stamp the right surface host per path
// without re-deriving which product it came from.
type UserDirRef struct {
	Path    string
	Product Product
}

// UserDirs returns every product's UserDir under home root h, in
// Products() order, skipping products that resolve to "" (an unknown
// h.OS). Callers get a fresh slice.
func UserDirs(h crossmount.HomeRoot) []UserDirRef {
	var refs []UserDirRef
	for _, p := range products {
		dir := UserDir(h, p)
		if dir == "" {
			continue
		}
		refs = append(refs, UserDirRef{Path: dir, Product: p})
	}
	return refs
}

// GlobalStorageDirs returns every product's globalStorage directory under
// home root h (UserDirs with "/globalStorage" appended), in the same order.
func GlobalStorageDirs(h crossmount.HomeRoot) []UserDirRef {
	return appendSubdir(UserDirs(h), "globalStorage")
}

// WorkspaceStorageDirs returns every product's workspaceStorage directory
// under home root h (UserDirs with "/workspaceStorage" appended), in the
// same order.
func WorkspaceStorageDirs(h crossmount.HomeRoot) []UserDirRef {
	return appendSubdir(UserDirs(h), "workspaceStorage")
}

func appendSubdir(refs []UserDirRef, subdir string) []UserDirRef {
	out := make([]UserDirRef, len(refs))
	for i, r := range refs {
		out[i] = UserDirRef{Path: filepath.Join(r.Path, subdir), Product: r.Product}
	}
	return out
}

// ProductForPath sniffs which Product a concrete path belongs to, by
// looking for that product's directory-name segment immediately followed
// by "User" (desktop products) or by "data" then "User" (Remote products),
// matched case-insensitively as whole path segments — never a substring,
// so "Code" never matches inside "Code - Insiders". Both "/" and "\"
// separators are accepted regardless of the running OS, so a Windows-style
// path can be sniffed on Linux and vice versa.
//
// It reports false when no product's segment sequence is present in path.
func ProductForPath(path string) (Product, bool) {
	segs := strings.Split(strings.ReplaceAll(path, "\\", "/"), "/")
	lower := make([]string, len(segs))
	for i, s := range segs {
		lower[i] = strings.ToLower(s)
	}

	for _, p := range products {
		dirLower := strings.ToLower(p.Dir)
		if p.Remote {
			for i := 0; i+2 < len(lower); i++ {
				if lower[i] == dirLower && lower[i+1] == "data" && lower[i+2] == "user" {
					return p, true
				}
			}
			continue
		}
		for i := 0; i+1 < len(lower); i++ {
			if lower[i] == dirLower && lower[i+1] == "user" {
				return p, true
			}
		}
	}
	return Product{}, false
}
