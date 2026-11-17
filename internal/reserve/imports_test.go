package reserve

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestImportsStayPure pins the reserve core free of I/O (CLAUDE.md "Module
// Boundaries" rule 1) and of its adopters: each ledger reads and writes its
// own rows and hands this package values, never the reverse.
func TestImportsStayPure(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		ForbiddenTrees: []string{
			"database/sql",
			"net/http",
			"github.com/fsnotify/fsnotify",
			"os/exec",
			"github.com/jackc/pgx/v5",
			"github.com/marmutapp/superbased-observer/internal/cloudserver",
			"github.com/marmutapp/superbased-observer/internal/aigateway",
			"github.com/marmutapp/superbased-observer/internal/orgserver",
		},
		Reason: "internal/reserve is pure; its ledgers import it, never the reverse",
	})
}
