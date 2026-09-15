package zed

import (
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// appDataName is the directory Zed creates under each platform's
// application-data root ("Zed" — capitalized on Windows and macOS; the
// Linux XDG path uses the lowercase spelling, added separately below
// since it is a DIFFERENT shape (~/.local/share, not ~/.config) than
// adapter.AppDataSpec's ShapeXDGConfig models).
const appDataName = "Zed"

// linuxDataDirName is Zed's lowercase XDG_DATA_HOME directory name.
const linuxDataDirName = "zed"

// defaultRoots returns the "threads" directory (the parent of
// threads.db) under every detected home, across every OS shape Zed is
// known to use. Windows and macOS reuse adapter.AppDataRoots (LOCALAPPDATA
// / Application Support — both grounded); Linux is composed by hand
// because Zed's Linux store lives under ~/.local/share, not ~/.config,
// which adapter.AppDataSpec has no shape for.
func defaultRoots() []string {
	spec := adapter.AppDataSpec{
		Name:   appDataName,
		Shapes: adapter.ShapeWindowsLocal | adapter.ShapeDarwinAppSupport,
	}

	seen := map[string]struct{}{}
	var roots []string
	add := func(p string) {
		if p == "" {
			return
		}
		if _, dup := seen[p]; dup {
			return
		}
		seen[p] = struct{}{}
		roots = append(roots, p)
	}

	for _, h := range crossmount.AllHomes() {
		for _, r := range adapter.AppDataRoots(h, spec) {
			add(filepath.Join(r, "threads"))
		}
		if h.OS == crossmount.OSLinux && h.Path != "" {
			add(filepath.Join(h.Path, ".local", "share", linuxDataDirName, "threads"))
		}
	}
	return roots
}
