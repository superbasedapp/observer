package winrelay

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins winrelay PURE: no network, no file system,
// no process, no database. The listener and the journal file live in
// internal/winrelaysvc.
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
			if strings.HasPrefix(p, "github.com/marmutapp/superbased-observer/internal/") && p != "github.com/marmutapp/superbased-observer/internal/integration" {
				return "only internal/integration allowed"
			}
			return ""
		},
		Reason: "winrelay is pure",
	})
}
