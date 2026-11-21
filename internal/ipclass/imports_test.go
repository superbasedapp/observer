package ipclass

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/ipclass as a pure stdlib leaf (CLAUDE.md
// module rule 1): the one owner of IP classification depends on no Observer
// package and no third party, so the same address classifies the same way on
// every OS and every binary.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		StdlibOnly: true,
		Reason:     "ipclass must be a pure standard-library leaf",
	})
}
