package planebadmission

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the family body pure (doc.go: wire shape and
// compile/validate only), like the other internal/policyfam packages: it
// shares the admission compiler as a library and must not pull
// internal/obs's evaluation engines into orgserver or orgclient.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		ForbiddenTrees: []string{
			"database/sql",
			"net/http",
			"github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/config",
			"github.com/marmutapp/superbased-observer/internal/obs",
		},
		Reason: "internal/policyfam/planebadmission must stay pure",
	})
}
