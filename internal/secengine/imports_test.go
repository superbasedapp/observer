package secengine

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins secengine PURE (CLAUDE.md rule 1): the
// caller hands it digests, listings, manifests and certificate bytes.
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
		Except:            []string{"github.com/marmutapp/superbased-observer/internal/update/content"},
		Reason:            "secengine is pure: the driver reads the binary, the tree and the manifest",
	})
}
