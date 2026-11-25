package procgroup

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the module boundary (CLAUDE.md section 1):
// this package starts and signals process groups and nothing else, so it
// imports only the standard library pieces that needs.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		AllowOnly: true,
		Allowed:   []string{"os/exec", "syscall", "time"},
		Reason:    "internal/procgroup only starts and signals process groups",
	})
}
