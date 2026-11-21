package warp

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins this vendor package pure (CLAUDE.md rule 1,
// enterprise vendor API plan section 3): SQL lives in the vendorconn store
// facade and outbound vendor HTTP only in the egress seam.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		ForbiddenTrees: []string{
			"database/sql",
			"net/http",
			"os/exec",
			"github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/orgserver",
		},
		Reason: "this package must stay pure",
	})
}
