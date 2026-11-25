package applane

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestImportsStayPure pins the app lane core free of I/O (CLAUDE.md "Module
// Boundaries" rule 1): the proxy and the obs wiring point call in with plain
// values.
func TestImportsStayPure(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		ForbiddenTrees: []string{
			"database/sql",
			"net/http",
			"github.com/fsnotify/fsnotify",
			"os/exec",
			"github.com/marmutapp/superbased-observer/internal/proxy",
			"github.com/marmutapp/superbased-observer/internal/obs",
			"github.com/marmutapp/superbased-observer/internal/store",
		},
		Reason: "internal/applane is pure; the proxy and the obs wiring point import it, never the reverse",
	})
}
