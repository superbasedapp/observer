package osvshardkey

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/secscan/osvshardkey pure (CLAUDE.md
// "Module Boundaries" rule 1): it is the key and the wire format only, so
// the publisher and the node's lookup lane both import it without pulling
// in a file, database, network or process dependency.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net/http",
			"net",
			"os",
			"os/exec",
			"io/ioutil",
			"github.com/fsnotify/fsnotify",
		},
		ForbiddenPrefixes: []string{
			"github.com/marmutapp/superbased-observer/",
		},
		Reason: "internal/secscan/osvshardkey must stay pure: the key and the wire format, no I/O and no sibling subsystem",
	})
}
