package pairing

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/pairing pure: the node and the org
// server both import it, and the caller owns every read.
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
		Reason: "internal/pairing must stay pure",
	})
}
