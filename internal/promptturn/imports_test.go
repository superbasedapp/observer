package promptturn

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/promptturn pure (CLAUDE.md module rule
// 1): it is shared by the node proxy, the guard and the org AI gateway, so it
// must never pull in a store, a network client or a file watcher.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net/http",
			"github.com/fsnotify/fsnotify",
		},
		Reason: "internal/promptturn must stay pure",
	})
}
