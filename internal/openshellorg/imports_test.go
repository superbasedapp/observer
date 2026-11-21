package openshellorg

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins the org-hosted OpenShell core pure: no
// database, no HTTP, no exec, no fsnotify and no OpenShell SDK (g1-design.md
// section 11.2 milestone 1; CLAUDE.md module rule 1). The store seam is
// internal/orgserver/openshellctl and the signer internal/orgserver/openshellidp.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql", "net/http", "net", "os", "os/exec", "syscall",
			"github.com/fsnotify/fsnotify",
		},
		ForbiddenTrees: []string{"github.com/NVIDIA/OpenShell/sdk/go"},
		Allowed: []string{
			"github.com/marmutapp/superbased-observer/internal/workspace",
			"github.com/marmutapp/superbased-observer/internal/sandboxopenshell",
			"github.com/marmutapp/superbased-observer/internal/sandboxvocab",
		},
		StdlibOnly: true,
		Reason:     "the org-hosted OpenShell core is pure; the ledger, the signer and the routes are openshellctl's and openshellidp's",
	})
}
