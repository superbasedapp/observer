package secsbom

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/secsbom pure (CLAUDE.md "Module
// Boundaries" rule 1; security coverage gaps plan section 3): it maps and
// parses bytes, the caller reads files. No network, file, database,
// process or fsnotify import, and no store.
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
		Reason: "internal/secsbom must stay pure: the caller reads the SBOM file and owns any I/O",
	})
}
