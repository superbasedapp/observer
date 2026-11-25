package pgthrow

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestImportsStayCycleFree pins pgthrow to the standard library and pgx: it
// must import nothing from this module, so internal/cloudserver/db's own
// tests can use it without an import cycle.
func TestImportsStayCycleFree(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"net/http", "database/sql", "github.com/fsnotify/fsnotify"},
		Custom: func(_, p string) string {
			if strings.HasPrefix(p, "github.com/marmutapp/superbased-observer/") {
				return "pgthrow may import nothing from this module (db's internal tests import it)"
			}
			return ""
		},
		Reason: "pgthrow is the cycle-free Postgres test fixture",
	})
}
