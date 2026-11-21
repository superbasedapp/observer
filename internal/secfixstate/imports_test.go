package secfixstate

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports pins the attempts file's owner to the standard library
// and the atomic file writer: no HTTP, no database, no subprocess, no file
// watcher and no other observer package, so the dashboard keeps owning the
// seams and this package owns only the file (CLAUDE.md module rules 1 and 4).
func TestPackageImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "net", "net/http", "os/exec", "github.com/fsnotify/fsnotify"},
		ForbiddenPrefixes: []string{
			"github.com/marmutapp/superbased-observer/",
		},
		Except: []string{
			"github.com/marmutapp/superbased-observer/internal/fsatomic",
		},
		Reason: "secfixstate is the Fix with an agent attempts file over plain values; the dashboard owns HTTP and the findings reads",
	})
}
