package winshell

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins winshell PURE (CLAUDE.md Module Boundaries
// #1): the PATH value and the file-exists probe are injected, so it needs
// nothing beyond strings.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		AllowOnly: true,
		Allowed:   []string{"strings"},
		Reason:    "winshell must stay pure: PATH and file probes are injected",
	})
}
