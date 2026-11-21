package secreachsvc

import (
	"io/fs"
	"path"
	"sort"
	"strings"
)

// gomods.go lists a project's go.mod files for the source-mode symbol
// check (3b-src runs once per go.mod, never over the tree in one run:
// spike RG-0 "Answer" item 2). It reads directory entries only.

// GoModLimits bound FindGoMods.
type GoModLimits struct {
	// MaxDirs caps the directories visited.
	MaxDirs int
	// MaxMods caps the go.mod files returned.
	MaxMods int
}

// DefaultGoModLimits are FindGoMods' bounds.
var DefaultGoModLimits = GoModLimits{MaxDirs: 20000, MaxMods: 256}

// skippedDir reports a directory the go command itself never builds as part
// of a module (vendor, testdata, a dot or underscore name) or that holds
// another ecosystem's packages.
func skippedDir(name string) bool {
	return name == "vendor" || name == "testdata" || name == "node_modules" ||
		strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")
}

// FindGoMods lists the project's go.mod files (paths relative to the root,
// forward slashes, sorted), one module each; truncated is set when a bound
// ended the walk early. Nothing but directory entries is read.
func FindGoMods(fsys fs.FS, lim GoModLimits) (mods []string, truncated bool) {
	if lim.MaxDirs <= 0 {
		lim.MaxDirs = DefaultGoModLimits.MaxDirs
	}
	if lim.MaxMods <= 0 {
		lim.MaxMods = DefaultGoModLimits.MaxMods
	}
	dirs := 0
	_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != "." && skippedDir(d.Name()) {
				return fs.SkipDir
			}
			dirs++
			if dirs > lim.MaxDirs {
				truncated = true
				return fs.SkipAll
			}
			return nil
		}
		if d.Name() != "go.mod" || !d.Type().IsRegular() {
			return nil
		}
		if len(mods) >= lim.MaxMods {
			truncated = true
			return fs.SkipAll
		}
		mods = append(mods, path.Clean(p))
		return nil
	})
	sort.Strings(mods)
	return mods, truncated
}
