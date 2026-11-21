package secfixtask

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Pure pins secfixtask to string building (CLAUDE.md rule
// 1): no database, network, subprocess, file watcher or observer package.
func TestPackageImports_Pure(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql", "net/http", "os", "os/exec", "github.com/fsnotify/fsnotify",
		},
		ForbiddenPrefixes: []string{"github.com/marmutapp/superbased-observer/internal/"},
		Reason:            "secfixtask builds a prompt from plain values; the dashboard loads them",
	})
}
