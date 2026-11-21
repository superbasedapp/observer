package promptadmit

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/promptadmit pure (CLAUDE.md module rule
// 1). It must also stay free of internal/obs: the org server consults it and
// the org server never imports obs (tests/invariant/obs_boundary_test.go).
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net/http",
			"github.com/fsnotify/fsnotify",
		},
		ForbiddenTrees: []string{"github.com/marmutapp/superbased-observer/internal/obs"},
		Reason:         "internal/promptadmit must stay pure",
	})
}
