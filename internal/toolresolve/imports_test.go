package toolresolve

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins toolresolve PURE (CLAUDE.md rule 1): all
// I/O is injected through Env, so not even os is allowed, and the only
// observer dependencies are internal/integration (the data it dispatches on)
// and internal/platform/winshim (a strings-only leaf that renders an install
// hint's command in the host shell's form).
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net/http",
			"os",
			"os/exec",
			"github.com/fsnotify/fsnotify",
		},
		ForbiddenPrefixes: []string{"github.com/marmutapp/superbased-observer/internal/"},
		Except: []string{
			"github.com/marmutapp/superbased-observer/internal/integration",
			"github.com/marmutapp/superbased-observer/internal/platform/winshim",
		},
		Reason: "toolresolve is pure, inject I/O via Env",
	})
}
