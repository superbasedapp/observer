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
	// "Cursor", "Windsurf", "Devin", "Kiro", "Qoder", "Trae". For a Remote
	// product, Dir instead holds the server directory name under the
	// home root — e.g. ".vscode-server", ".cursor-server".
	Dir string
	// Host is the lowercase surface-host token this product stamps
	// alongside models.SurfaceIDE — e.g. "vscode", "vscode-insiders",
	// "vscodium", "cursor", "windsurf", "kiro", "qoder", "trae",
	// "vscode-remote", "cursor-remote", "windsurf-remote", "kiro-remote".
	Host string
	// Remote marks a server-side layout (VS Code Server / Cursor
	// Server) reached over SSH, WSL, or a dev container, as opposed to
	// a desktop install.
	Remote bool
	// ExtensionsDir is the per-user extensions directory relative to the
	// home root, the same on every OS ("" when not grounded: the product's
	// extensions are not enumerated). VS Code documents
	// %USERPROFILE%\.vscode\extensions on Windows and ~/.vscode/extensions on
	// macOS and Linux ("Where are extensions installed?",
	// code.visualstudio.com/docs/editor/extension-marketplace), the
	// .vscode-insiders and .vscode-server spellings beside it; VSCodium
	// keeps them in ~/.vscode-oss/extensions (its DOCS.md), Cursor in
	// ~/.cursor/extensions and Windsurf in ~/.windsurf/extensions.
	ExtensionsDir string
	// ExtensionsEnv marks a product whose extensions directory the
	// VSCODE_EXTENSIONS variable relocates (ExtensionsEnvVar, FU-170): VS
	// Code's environment service reads it before the default
	// (src/vs/platform/environment/node/environmentService.ts, extensionsPath:
	// --extensions-dir, then VSCODE_EXTENSIONS, then the product's own
	// folder). Set for VS Code and VS Code Insiders only; the forks run the
	// same code, but none is grounded here, so their default stays.
	ExtensionsEnv bool
}

// ExtensionsEnvVar is the variable that relocates the extensions directory
// of a product with ExtensionsEnv (FU-170). Only an absolute value is
// followed; a relative one is read against VS Code's own working directory,
// which Observer cannot know, so the product's extensions are then not read
// at all, as with the other relocation variables.
const ExtensionsEnvVar = "VSCODE_EXTENSIONS"

// products is the ordered table of every VS Code-family product this
// package enumerates: desktop products first (in the order an operator is
// most likely to have them installed), then remote server layouts.
var products = []Product{
	{Dir: "Code", Host: "vscode", ExtensionsDir: ".vscode/extensions", ExtensionsEnv: true},
	{Dir: "Code - Insiders", Host: "vscode-insiders", ExtensionsDir: ".vscode-insiders/extensions", ExtensionsEnv: true},
	{Dir: "VSCodium", Host: "vscodium", ExtensionsDir: ".vscode-oss/extensions"},
	{Dir: "Cursor", Host: "cursor", ExtensionsDir: ".cursor/extensions"},
	{Dir: "Windsurf", Host: "windsurf", ExtensionsDir: ".windsurf/extensions"},
	// Devin Desktop, the renamed Windsurf fork: its Electron user-data dir is
	// "Devin" (grounded on Windows 2026-09-03, internal/adapter/devin/
	// surface.go), and its host token is the one the devin adapter already
	// stamps. Extensions inside it (Cline, Copilot, Kilo) keep their
	// globalStorage under Devin/User, not Windsurf/User, so without this row
	// they were never enumerated (surface-gap S-10, NEW-9; extension capture
	// inside Devin Desktop is unverified live). The macOS and Linux dirs
	// follow the same Electron ladder, also unverified live. On Windows the
	// directory is the Devin CLI's %APPDATA%\devin too (NTFS folds case);
	// only its User subtree is a product dir.
	{Dir: "Devin", Host: "devin-desktop"},
	{Dir: "Kiro", Host: "kiro"},
	{Dir: "Qoder", Host: "qoder"},
	{Dir: "Trae", Host: "trae"},
	{Dir: ".vscode-server", Host: "vscode-remote", Remote: true, ExtensionsDir: ".vscode-server/extensions"},
	{Dir: ".cursor-server", Host: "cursor-remote", Remote: true, ExtensionsDir: ".cursor-server/extensions"},
	// The Windsurf and Kiro server layouts a Remote (SSH / WSL / dev
	// container) window installs on the remote side (surface-gap IDE-1, D7).
	// Both forks keep VS Code Server's <home>/<dir>/data/User shape; neither
	// directory is grounded live yet (live checks WSL-4 / LC13-W), so the
	// rows only widen what the readers look at. Their host tokens are in the
	// org wire's reviewed surface allow-list (orgpush.go knownSurfaceHosts),
	// so they ship as themselves, like vscode-remote and cursor-remote.
	{Dir: ".windsurf-server", Host: "windsurf-remote", Remote: true},
	{Dir: ".kiro-server", Host: "kiro-remote", Remote: true},
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

// ExtensionsDirs returns every product's per-user extensions directory
// under home root h, in Products() order, skipping a product whose
// ExtensionsDir is not grounded and a home whose OS is unknown (FU-152).
// getenv is the caller's environment for h (nil reads none): a product with
// ExtensionsEnv whose ExtensionsEnvVar is set reads that directory instead
// when the value is absolute, and nothing when it is relative (FU-170). A
// directory two products share is listed once, for the first.
func ExtensionsDirs(h crossmount.HomeRoot, getenv func(string) string) []UserDirRef {
	switch h.OS {
	case crossmount.OSWindows, crossmount.OSDarwin, crossmount.OSLinux:
	default:
		return nil
	}
	relocated := ""
	if getenv != nil {
		relocated = getenv(ExtensionsEnvVar)
	}
	var refs []UserDirRef
	seen := map[string]bool{}
	for _, p := range products {
		if p.ExtensionsDir == "" {
			continue
		}
		dir := filepath.Join(h.Path, filepath.FromSlash(p.ExtensionsDir))
		if p.ExtensionsEnv && relocated != "" {
			if !filepath.IsAbs(relocated) {
				continue
			}
			dir = filepath.Clean(relocated)
		}
		if seen[dir] {
			continue
		}
		seen[dir] = true
		refs = append(refs, UserDirRef{Path: dir, Product: p})
	}
	return refs
}

// ExtensionIDFromDir returns the lowercase extension id (publisher.name) an
// installed extension's directory name carries: VS Code names it
// <publisher>.<name>-<version>[-<platform>], so the id is everything before
// the first "-" segment that starts with a digit. ok is false for a name
// that is not that shape (a dotfile such as .obsolete, extensions.json, a
// name with no version or no publisher).
func ExtensionIDFromDir(name string) (string, bool) {
	if name == "" || strings.HasPrefix(name, ".") {
		return "", false
	}
	segs := strings.Split(name, "-")
	for i := 1; i < len(segs); i++ {
		if segs[i] != "" && segs[i][0] >= '0' && segs[i][0] <= '9' {
			id := strings.ToLower(strings.Join(segs[:i], "-"))
			dot := strings.Index(id, ".")
			if dot <= 0 || dot == len(id)-1 {
				return "", false
			}
			return id, true
		}
	}
	return "", false
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
