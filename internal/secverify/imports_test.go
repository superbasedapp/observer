package secverify

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the verify core as pure: it judges bytes the
// cmd layer read, and never reads a file, the environment, the network or
// a database itself (the hermetic mode of security plan 7.9 rests on it).
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"os",
			"os/exec",
			"net",
			"net/http",
			"database/sql",
			"github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/config",
		},
		Reason: "keep internal/secverify pure and hermetic",
	})
}
