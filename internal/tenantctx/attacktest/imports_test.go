package attacktest

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestImportsStayDriverFree pins the kit free of any database driver and of
// its adopters: it drives a Session interface each adopter implements over
// its own connection, so one kit serves database/sql and pgx alike.
func TestImportsStayDriverFree(t *testing.T) {
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
		Reason: "the attack kit is driver-agnostic",
	})
}
