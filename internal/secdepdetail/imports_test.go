package secdepdetail

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/secdepdetail pure (CLAUDE.md
// "Module Boundaries" rule 1): the lockfile read and the OSV record read
// are injected through Input, so the package opens no file, no database
// and no connection of its own.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net/http",
			"os",
			"os/exec",
			"io/ioutil",
			"github.com/fsnotify/fsnotify",
		},
		Reason: "internal/secdepdetail must stay pure: I/O is injected through Input",
	})
}
