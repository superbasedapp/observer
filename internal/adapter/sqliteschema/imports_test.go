package sqliteschema

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins sqliteschema to catalogue reads through the
// caller's *sql.DB: no HTTP, fsnotify, file access, store or db package.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"net/http",
			"os",
			"github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/store",
			"github.com/marmutapp/superbased-observer/internal/db",
		},
		Reason: "internal/adapter/sqliteschema only probes a caller-opened store",
	})
}
