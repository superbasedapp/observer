package docpos

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins docpos to the standard library: it parses Go
// source with go/parser and needs nothing else.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		StdlibOnly: true,
		Reason:     "internal/testsupport/docpos is a standard-library test helper",
	})
}
