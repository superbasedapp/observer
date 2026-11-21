package attachrule

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/attachrule pure: the caller supplies
// all state and acts on the Decision.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net/http",
			"github.com/fsnotify/fsnotify",
			"os",
			"os/exec",
			"io/ioutil",
			"io/fs",
		},
		Reason: "internal/attachrule must stay pure",
	})
}
