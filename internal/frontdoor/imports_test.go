package frontdoor

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/frontdoor pure: the caller supplies
// the enrolment and the sign-in state.
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
		Reason: "internal/frontdoor must stay pure",
	})
}
