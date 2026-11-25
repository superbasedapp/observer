package fstree

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins fstree to the standard library: a test helper
// that writes files needs nothing else, and an observer import here could
// pull a production package into every test that uses it.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		StdlibOnly: true,
		Reason:     "internal/testsupport/fstree is a standard-library test helper",
	})
}
