package secrulepack

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins secrulepack PURE (CLAUDE.md rule 1): it
// validates bytes its caller passes and the embedded floor; it opens no
// file, starts no process and makes no network call.
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
			"github.com/marmutapp/superbased-observer/internal/policy", "github.com/marmutapp/superbased-observer/internal/seccorpus",
			// The test-path class table (lane SEC-P4), itself stdlib only.
			"github.com/marmutapp/superbased-observer/internal/sectestpath",
		},
		Reason: "secrulepack is pure: the driver writes the pack to disk and runs the engine",
	})
}
