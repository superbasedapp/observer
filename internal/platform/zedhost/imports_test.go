package zedhost

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins zedhost as pure data (CLAUDE.md Module
// Boundaries #1).
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		AllowOnly: true,
		Allowed: []string{
			"github.com/marmutapp/superbased-observer/internal/models",
		},
		Reason: "zedhost must stay pure",
	})
}
