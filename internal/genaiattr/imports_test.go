package genaiattr

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the vocabulary pure (CLAUDE.md "Module
// Boundaries" rule 1): no I/O, and never internal/obs, so the node mapper,
// the gateway mapper and the OTel-direct path can all import it without
// crossing the obs boundary (tests/invariant/obs_boundary_test.go). Its only
// in-repo import is internal/otelident, the identity-key owner.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden:         []string{"database/sql", "net/http", "net", "os", "os/exec", "github.com/fsnotify/fsnotify"},
		ForbiddenTrees:    []string{"github.com/marmutapp/superbased-observer/internal/obs"},
		ForbiddenPrefixes: []string{"github.com/marmutapp/superbased-observer/"},
		Except:            []string{"github.com/marmutapp/superbased-observer/internal/otelident"},
		Reason:            "internal/genaiattr is a pure vocabulary",
	})
}
