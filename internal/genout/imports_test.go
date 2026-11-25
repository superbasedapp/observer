package genout

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/genout to the standard library: it
// is linked into every code generator and must stay a plain file writer.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		StdlibOnly: true,
		Forbidden: []string{
			"database/sql",
			"net/http",
		},
		Reason: "internal/genout is a stdlib-only generator helper",
	})
}
