package clinecli

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter/mirrorbase"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// allHomesFunc is the test seam over crossmount.AllHomes — tests
// override it to assert foreign-mount detection without depending on
// the host's filesystem layout. Same shape as opencode.allHomesFunc.
var allHomesFunc = crossmount.AllHomes

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

// mirrorSpec is the allow-list mirror of the Cline CLI store (sessions.db): every table this
// package queries and nothing else. A query on a new table must add it
// here, or the foreign-mount mirror silently lacks it;
// mirrortest.AssertSpecCoversQueries pins that.
var mirrorSpec = mirrorbase.Spec{
	Dir:    "clinecli-mirror",
	File:   "sessions.db",
	Tables: []string{"sessions"},
}

// isForeignMountPath reports whether path lives under a
// crossmount-detected non-native home. Both directions are covered:
// `/mnt/c/Users/<u>/…` on a WSL2 Linux host, and
// `\\wsl.localhost\<distro>\home\<u>\…` on a Windows host. The
// watcher dispatches both native and foreign-mount homes into the
// same adapter; only the foreign ones need the mirror — native
// paths open directly with no overhead.
func isForeignMountPath(path string) bool {
	for _, h := range allHomesFunc() {
		if h.Origin == "native" {
			continue
		}
		// Accept both the OS-native separator and forward slash —
		// /mnt/c uses forward slashes regardless of the foreign OS.
		sep := string(filepath.Separator)
		if strings.HasPrefix(path, h.Path+sep) || strings.HasPrefix(path, h.Path+"/") {
			return true
		}
	}
	return false
}
