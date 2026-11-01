package protectedhome

import (
	"path/filepath"
	"strings"
)

// table maps a GOOS value to the names of the folders directly under the
// home that the OS guards behind a privacy prompt. An OS with no row has
// none. Names compare case-insensitively (APFS is case-insensitive by
// default). "Library" covers ~/Library/Mobile Documents, the iCloud Drive
// store; "Mobile Documents" is listed too for a home that links it to the
// top level.
var table = map[string][]string{
	"darwin": {
		"Desktop",
		"Documents",
		"Downloads",
		"Library",
		"Movies",
		"Music",
		"Pictures",
		"Mobile Documents",
		"iCloud Drive",
	},
}

// Names returns the protected folder names for goos (a copy), or nil when
// the OS guards none.
func Names(goos string) []string {
	src := table[goos]
	if len(src) == 0 {
		return nil
	}
	return append([]string(nil), src...)
}

// Protected reports whether name, a folder directly under the home, is one
// goos guards behind a privacy prompt.
func Protected(goos, name string) bool {
	for _, n := range table[goos] {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}

// SkipChild reports whether a home walk on goos should step around the
// folder name directly under home. It is false for a folder the OS does not
// guard, and false for a guarded folder that holds one of keep (a configured
// or already-known project root): the user has worked there, so the folder
// is already granted or the walk has a reason to ask.
func SkipChild(goos, home, name string, keep []string) bool {
	if !Protected(goos, name) {
		return false
	}
	dir := filepath.Clean(filepath.Join(home, name))
	for _, k := range keep {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if under(filepath.Clean(k), dir) {
			return false
		}
	}
	return true
}

// under reports whether p is dir or lies below it, case-insensitively.
func under(p, dir string) bool {
	if strings.EqualFold(p, dir) {
		return true
	}
	prefix := dir + string(filepath.Separator)
	return len(p) > len(prefix) && strings.EqualFold(p[:len(prefix)], prefix)
}
