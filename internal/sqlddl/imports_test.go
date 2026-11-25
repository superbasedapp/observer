package sqlddl

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/sqlddl pure: it is text in, text out,
// and is linked into the structural checker, whose own pin forbids os and
// path/filepath.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		StdlibOnly: true,
		Forbidden: []string{
			"database/sql",
			"net",
			"net/http",
			"os",
			"os/exec",
			"path/filepath",
		},
		Reason: "internal/sqlddl is a pure text helper",
	})
}
