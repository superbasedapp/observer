package tenantctx

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestImportsStayPure pins tenantctx free of I/O (CLAUDE.md "Module
// Boundaries" rule 1) and of its adopters: the token and the signer are
// pure, and each adopter executes the statement with its own driver.
func TestImportsStayPure(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		ForbiddenTrees: []string{
			"database/sql",
			"net/http",
			"github.com/fsnotify/fsnotify",
			"os/exec",
			"github.com/jackc/pgx/v5",
			"github.com/marmutapp/superbased-observer/internal/orgserver",
			"github.com/marmutapp/superbased-observer/internal/cloudserver",
		},
		Reason: "tenantctx is pure; its adopters import it, never the reverse",
	})
}
