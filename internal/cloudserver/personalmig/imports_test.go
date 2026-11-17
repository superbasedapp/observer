package personalmig

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the package pure (CLAUDE.md rule 1): the store
// reads the facts and the command writes the files.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		ForbiddenTrees: []string{
			"database/sql",
			"net",
			"os",
			"github.com/fsnotify/fsnotify",
			"github.com/jackc/pgx",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/store",
		},
		Reason: "internal/cloudserver/personalmig is the pure core of migrate-personal",
	})
}
