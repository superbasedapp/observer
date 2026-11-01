package kirocli

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter/mirrorbase"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// allHomesFunc is the test seam over crossmount.AllHomes — tests
// override it to assert foreign-mount detection without depending on
// the host's filesystem layout. Same shape as clinecli.allHomesFunc.
var allHomesFunc = crossmount.AllHomes

// sessionsSubpath is the PARENT session directory shared by BOTH
// file-backed layouts, identical on every OS (Windows uses
// C:\Users\<u>\.kiro\sessions — NOT %LOCALAPPDATA%):
//
//	<home>/.kiro/sessions/cli/<uuid>.{json,jsonl}          CLI flat bundle
//	<home>/.kiro/sessions/<bucket>/<sid>/messages.jsonl    Kiro IDE
//
// Watching the PARENT (not `.../sessions/cli`) is what brings the IDE
// subtree in: adapter.UnderAnyWatchRoot is a path-PREFIX test, so the
// flat bundles keep matching unchanged, and one root avoids the nested
// duplicate-watch a `cli` + `sessions` pair would create.
var sessionsSubpath = filepath.Join(".kiro", "sessions")

// defaultRoots returns the two watch roots per cross-mount-resolved
// home: the session dir (`<home>/.kiro/sessions`, identical on every
// OS, covering both the CLI flat bundles and the Kiro IDE subtree) and
// the SQLite data dir, whose location is OS-shaped:
//
//	linux/darwin home → <home>/.local/share/kiro-cli
//	windows home      → <home>/AppData/Local/Kiro-Cli
//
// The OS is the LOGICAL OS of the home (crossmount.HomeRoot.OS), not
// runtime.GOOS — so a WSL2 observer reaches a Windows-side store at
// /mnt/c/Users/<u>/AppData/Local/Kiro-Cli and a Windows observer
// reaches a WSL store at \\wsl.localhost\<distro>\home\<u>\.local\share
// \kiro-cli.
func defaultRoots() []string {
	var roots []string
	seen := map[string]struct{}{}
	add := func(p string) {
		if p == "" {
			return
		}
		p = filepath.Clean(p)
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		roots = append(roots, p)
	}

	for _, h := range allHomesFunc() {
		if h.Path == "" {
			continue
		}
		add(filepath.Join(h.Path, sessionsSubpath))
		add(filepath.Join(append([]string{h.Path}, sqliteDataSubdir(h.OS)...)...))
	}
	return roots
}

// sqliteDataSubdir returns the path segments of the kiro-cli SQLite
// data directory for a home following the given logical OS.
func sqliteDataSubdir(homeOS string) []string {
	if homeOS == crossmount.OSWindows {
		return []string{"AppData", "Local", "Kiro-Cli"}
	}
	return []string{".local", "share", "kiro-cli"}
}

// stageMirrorIfForeign returns srcDB unchanged when it is native. A foreign-mount
// store (a Windows-side store read by a WSL observer over /mnt/c, or
// the reverse), which modernc.org/sqlite cannot open in place while the
// vendor process writes its WAL, is read through a filtered local
// mirror built by mirrorbase.Stage: only the tables in mirrorSpec are
// kept, so the store's other tables (credentials included) never leave
// the vendor's file.
func stageMirrorIfForeign(srcDB string) (string, error) {
	if !isForeignMountPath(srcDB) {
		return srcDB, nil
	}
	return mirrorbase.Stage(context.Background(), srcDB, mirrorSpec)
}

// mirrorSpec is the allow-list mirror of the Kiro CLI store (data.sqlite3, whose auth_kv table holds sign-in tokens): every table this
// package queries and nothing else. A query on a new table must add it
// here, or the foreign-mount mirror silently lacks it;
// mirrortest.AssertSpecCoversQueries pins that.
var mirrorSpec = mirrorbase.Spec{
	Dir:    "kirocli-mirror",
	File:   "data.sqlite3",
	Tables: []string{"conversations_v2"},
}

// isForeignMountPath reports whether path lives under a crossmount-
// detected non-native home. Both bridge directions are covered.
func isForeignMountPath(path string) bool {
	for _, h := range allHomesFunc() {
		if h.Origin == "native" {
			continue
		}
		sep := string(filepath.Separator)
		if strings.HasPrefix(path, h.Path+sep) || strings.HasPrefix(path, h.Path+"/") {
			return true
		}
	}
	return false
}
