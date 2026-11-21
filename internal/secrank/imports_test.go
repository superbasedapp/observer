package secrank

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/secrank pure (CLAUDE.md "Module
// Boundaries" rule 1): keys in, a permutation out.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net/http",
			"net",
			"os",
			"os/exec",
			"io/ioutil",
			"path/filepath",
			"github.com/fsnotify/fsnotify",
		},
		Reason: "internal/secrank must stay pure: the signals are computed by the caller",
	})
}
