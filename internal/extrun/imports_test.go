package extrun

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins extrun PURE (CLAUDE.md rule 1): the
// resolver, inspector, hasher, environment read and process start are all
// injected, so no OS, exec, network or database package may be imported.
// The only observer dependencies are the data it resolves with.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net",
			"net/http",
			"os",
			"os/exec",
			"syscall",
			"github.com/fsnotify/fsnotify",
		},
		ForbiddenPrefixes: []string{"github.com/marmutapp/superbased-observer/internal/", "golang.org/x/sys"},
		Except: []string{
			"github.com/marmutapp/superbased-observer/internal/integration",
			"github.com/marmutapp/superbased-observer/internal/toolresolve",
		},
		Reason: "extrun is pure, inject I/O through the Runner's fields",
	})
}
