package seclicense

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/seclicense pure (CLAUDE.md "Module
// Boundaries" rule 1): it reads bytes the caller supplies and decides; the
// walk over a project and the recording of findings live in the caller.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net",
			"net/http",
			"os",
			"os/exec",
			"io/ioutil",
			"syscall",
			"github.com/fsnotify/fsnotify",
		},
		ForbiddenTrees: []string{
			"github.com/marmutapp/superbased-observer/internal/store",
		},
		Reason: "internal/seclicense must stay pure: the caller reads files and records findings",
	})
}
