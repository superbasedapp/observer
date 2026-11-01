package proxyauth

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins proxyauth PURE: no network listener, no
// file system, no process, no database, no other internal package.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net",
			"net/http",
			"net/http/httputil",
			"os",
			"os/exec",
			"github.com/fsnotify/fsnotify",
		},
		Custom: func(_, p string) string {
			if strings.HasPrefix(p, "github.com/marmutapp/superbased-observer/internal/") {
				return "proxyauth imports no internal package"
			}
			return ""
		},
		Reason: "proxyauth is pure",
	})
}
