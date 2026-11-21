package enrichbudget

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestImportsStayPure pins enrichbudget free of I/O (CLAUDE.md "Module
// Boundaries" rule 1): the store reads rows and hands values in.
func TestImportsStayPure(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		ForbiddenTrees: []string{
			"database/sql",
			"net/http",
			"os/exec",
			"github.com/fsnotify/fsnotify",
			"github.com/jackc/pgx/v5",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/store",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/api",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs",
		},
		Reason: "internal/cloudserver/enrichbudget is pure; the store and the API import it, never the reverse",
	})
}
