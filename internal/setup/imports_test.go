package setup

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/setup as pure decisions (CLAUDE.md
// rule 1): the registry, the Path, processes and files are read and written
// by cmd/observer, never here.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net/http",
			"net",
			"os",
			"os/exec",
			"golang.org/x/sys/windows",
			"golang.org/x/sys/windows/registry",
			"github.com/fsnotify/fsnotify",
		},
		Reason: "internal/setup must stay pure (the cmd layer does every read and write)",
	})
}
