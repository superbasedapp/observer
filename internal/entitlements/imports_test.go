package entitlements

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the package pure (CLAUDE.md rule 1): no SQL,
// no HTTP, no fsnotify, no exec. Its only project imports are the component
// catalog (the capability keys) and the document envelope.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Dirs: []string{".", "planlint"},
		ForbiddenTrees: []string{
			"database/sql",
			"net",
			"os",
			"github.com/fsnotify/fsnotify",
			"github.com/jackc/pgx",
		},
		Reason: "internal/entitlements is the pure core of signed entitlements",
	})
}
