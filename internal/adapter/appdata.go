package adapter

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// AppDataShape is one per-OS application-data directory convention a
// tool may follow. Shapes compose as a bit set so a spec can declare
// more than one (a Windows app that writes both Roaming and Local, for
// instance) without growing a field per combination.
type AppDataShape uint8

const (
	// ShapeWindowsRoaming is <home>/AppData/Roaming/<Name>, the
	// %APPDATA% convention. On a NATIVE Windows home the %APPDATA%
	// environment variable wins when set, because a roaming profile or
	// a folder redirection can put it off the default drive — the same
	// rule vscodehost.UserDir and jetbrainshost.VendorRoot apply.
	ShapeWindowsRoaming AppDataShape = 1 << iota

	// ShapeWindowsLocal is <home>/AppData/Local/<Name>, the
	// %LOCALAPPDATA% convention.
	ShapeWindowsLocal

	// ShapeDarwinAppSupport is <home>/Library/Application Support/<Name>.
	ShapeDarwinAppSupport

	// ShapeXDGConfig is <home>/.config/<Name>, the XDG convention.
	ShapeXDGConfig
)

// AppDataSpec declares how ONE tool spells its per-user
// application-data directory, and which OSes it is known to use.
//
// The point of the type is that the declaration is a TABLE, evaluated
// against the home's LOGICAL OS — never a blind fan-out of every shape
// under every home. That distinction is invisible on a single-OS box
// and load-bearing on a WSL2 daemon: crossmount hands the adapter
// Windows homes reached over /mnt/c alongside the native Linux one,
// and a spec that emits "Library/Application Support" under a Windows
// home has produced a path that cannot exist on any host, ever.
type AppDataSpec struct {
	// Name is the directory the tool creates ("com.qoder.app.stable",
	// "Grok Bot"). It is used verbatim under whichever parent each
	// shape names. An empty Name yields no roots.
	Name string

	// Shapes is the set of conventions this tool is known — or, when
	// documented as such at the call site, believed — to follow. Only
	// the shapes belonging to a home's OS are emitted for that home:
	// ShapeWindowsRoaming/ShapeWindowsLocal for a Windows home,
	// ShapeDarwinAppSupport for a darwin home, ShapeXDGConfig for a
	// linux home.
	//
	// Declaring a shape the tool does not use costs one inert watch
	// root on the matching OS; OMITTING one it does use costs silent
	// zero-capture there. Neither is free, so declare what is grounded
	// and note the guesses.
	Shapes AppDataShape

	// XDGOnWindows opts the tool into ShapeXDGConfig for a WINDOWS
	// home as well — <home>/.config/<Name>.
	//
	// This is a real shape for the handful of tools that mirror XDG on
	// every platform rather than following the Windows convention
	// (Kilo Code is the in-tree example: its store is
	// ~/.local/share/kilo/kilo.db on Linux, macOS AND Windows). It is
	// an explicit per-tool opt-in precisely because it is the
	// exception — the default must not be "try the XDG shape under
	// Windows too, just in case", which is how a WSL daemon ends up
	// registering /mnt/c/Users/<u>/.config/<app> for tools that have
	// never written such a path.
	//
	// Only set it with evidence. ShapeXDGConfig must be in Shapes for
	// it to have any effect.
	XDGOnWindows bool
}

// AppDataRoots returns the application-data directories spec names
// under home root h, restricted to the shapes that belong to h's
// logical OS.
//
// Results are Clean-ed and de-duplicated within the call, in a stable
// order (Roaming, Local, Application Support, .config). A home with an
// empty path, an OS this ladder does not model, or a spec with an
// empty Name yields nil. Callers get a fresh slice.
//
// Non-existence is NOT a filter here: adapters return their canonical
// roots regardless of installed state (the Adapter contract), and the
// watcher drops the missing ones. What this helper removes is the
// class of root that is not merely absent but IMPOSSIBLE — a macOS
// path under a Windows home.
//
// Typical use, fanning across every cross-mount home:
//
//	for _, h := range crossmount.AllHomes() {
//		roots = append(roots, adapter.AppDataRoots(h, spec)...)
//	}
//	return adapter.DedupRootsByIdentity(roots)
func AppDataRoots(h crossmount.HomeRoot, spec AppDataSpec) []string {
	if h.Path == "" || spec.Name == "" || spec.Shapes == 0 {
		return nil
	}

	var out []string
	seen := make(map[string]struct{}, 4)
	add := func(p string) {
		if p == "" {
			return
		}
		p = filepath.Clean(p)
		key := rootIdentityKey(p)
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		out = append(out, p)
	}

	switch h.OS {
	case crossmount.OSWindows:
		if spec.Shapes&ShapeWindowsRoaming != 0 {
			if env := nativeWindowsEnvDir(h, "APPDATA"); env != "" {
				add(filepath.Join(env, spec.Name))
			}
			add(filepath.Join(h.Path, "AppData", "Roaming", spec.Name))
		}
		if spec.Shapes&ShapeWindowsLocal != 0 {
			if env := nativeWindowsEnvDir(h, "LOCALAPPDATA"); env != "" {
				add(filepath.Join(env, spec.Name))
			}
			add(filepath.Join(h.Path, "AppData", "Local", spec.Name))
		}
		if spec.XDGOnWindows && spec.Shapes&ShapeXDGConfig != 0 {
			add(filepath.Join(h.Path, ".config", spec.Name))
		}
	case crossmount.OSDarwin:
		if spec.Shapes&ShapeDarwinAppSupport != 0 {
			add(filepath.Join(h.Path, "Library", "Application Support", spec.Name))
		}
	case crossmount.OSLinux:
		if spec.Shapes&ShapeXDGConfig != 0 {
			add(filepath.Join(h.Path, ".config", spec.Name))
		}
	}
	return out
}

// nativeWindowsEnvDir returns the value of a Windows application-data
// environment variable, but ONLY for the native home of a process that
// is itself running on Windows. For a foreign home reached over
// /mnt/c the running process's %APPDATA% describes a different
// profile entirely, so consulting it there would point one user's
// watch root at another user's directory.
func nativeWindowsEnvDir(h crossmount.HomeRoot, name string) string {
	if h.Origin != "native" || runtime.GOOS != "windows" {
		return ""
	}
	return strings.TrimSpace(os.Getenv(name))
}
