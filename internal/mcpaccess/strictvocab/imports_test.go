package strictvocab

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the purity the package doc states: no SQL, no
// HTTP, no file watching and no subprocesses (CLAUDE.md rule 1).
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		ForbiddenTrees: []string{
			"database/sql",
			"net/http",
			"github.com/fsnotify/fsnotify",
			"os/exec",
		},
		Reason: "internal/mcpaccess/strictvocab is a pure stdlib-only vocabulary",
	})
}
