package devin

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/adapter/mirrorbase"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/sqlitedsn"
)

// allHomesFunc is the test seam over crossmount.AllHomes — tests override
// it to assert foreign-mount detection without depending on the host's
// filesystem layout. Same shape as kirocli.allHomesFunc / crush.allHomesFunc.
var allHomesFunc = crossmount.AllHomes

// storeSubdir returns the path segments of Devin's CLI store directory for
// a home following the given logical OS. Devin uses XDG on Linux/macOS
// (~/.local/share/devin/cli) and %APPDATA% (AppData\Roaming\devin\cli) on
// Windows.
func storeSubdir(homeOS string) []string {
	if homeOS == crossmount.OSWindows {
		return []string{"AppData", "Roaming", "devin", "cli"}
	}
	return []string{".local", "share", "devin", "cli"}
}

// defaultRoots returns one watch root per cross-mount-resolved home: the
// Devin CLI store directory. The OS is the LOGICAL OS of the home
// (crossmount.HomeRoot.OS), not runtime.GOOS — so a WSL2 observer reaches
// a Windows-side store at /mnt/c/Users/<u>/AppData/Roaming/devin/cli and a
// Windows observer reaches a WSL store at
// \\wsl.localhost\<distro>\home\<u>\.local\share\devin\cli. Non-existent
// dirs are inert (the watcher skips them at registry time).
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
		add(filepath.Join(append([]string{h.Path}, storeSubdir(h.OS)...)...))
	}
	return roots
}

// resolveDBPath maps a -wal/-shm sibling event back to the main
// sessions.db.
func resolveDBPath(path string) string {
	base := strings.ToLower(filepath.Base(path))
	if base == "sessions.db-wal" || base == "sessions.db-shm" {
		return filepath.Join(filepath.Dir(path), "sessions.db")
	}
	return path
}

// openReadOnlyDB opens the sessions.db read-only, staging a local mirror
// first when the source is a foreign mount.
func openReadOnlyDB(path string) (*sql.DB, error) {
	actual, err := stageMirrorIfForeign(path)
	if err != nil {
		return nil, fmt.Errorf("devin.stageMirror: %w", err)
	}
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(2000)", sqlitedsn.Escape(actual))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
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

// mirrorSpec is the allow-list mirror of the Devin store (sessions.db): every table this
// package queries and nothing else. A query on a new table must add it
// here, or the foreign-mount mirror silently lacks it;
// mirrortest.AssertSpecCoversQueries pins that.
var mirrorSpec = mirrorbase.Spec{
	Dir:    "devin-mirror",
	File:   "sessions.db",
	Tables: []string{"sessions", "message_nodes"},
}

// isForeignMountPath reports whether path lives under a crossmount-detected
// non-native home. Covers both bridge directions (/mnt/c on WSL2, and
// \\wsl.localhost\ on Windows).
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
