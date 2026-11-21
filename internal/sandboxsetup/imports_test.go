package sandboxsetup

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins sandboxsetup pure (CLAUDE.md rule 1): the
// caller gathers facts and runs steps; this package only plans.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden:  []string{"database/sql", "net/http", "net", "os", "os/exec", "github.com/fsnotify/fsnotify"},
		StdlibOnly: true,
		Allowed: []string{
			"github.com/marmutapp/superbased-observer/internal/toolinstall",
			"github.com/marmutapp/superbased-observer/internal/sandboxbackend",
			"github.com/marmutapp/superbased-observer/internal/sandboxselect",
			"github.com/marmutapp/superbased-observer/internal/sandboxvocab",
		},
		Reason: "sandbox setup planning is pure: facts in, a plan out",
	})
}
