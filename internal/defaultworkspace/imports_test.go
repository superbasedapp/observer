package defaultworkspace

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins defaultworkspace to folder checks and
// folder set-up (CLAUDE.md rule 1): no subprocess (git init is injected),
// no database, no network, no file watcher, and only internal/git among
// observer packages.
func TestPackageImports_Bounded(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql", "net/http", "os/exec", "github.com/fsnotify/fsnotify",
		},
		ForbiddenPrefixes: []string{"github.com/marmutapp/superbased-observer/internal/"},
		Except: []string{
			"github.com/marmutapp/superbased-observer/internal/git",
		},
		Reason: "defaultworkspace checks and creates one folder; it never runs anything or calls out",
	})
}
