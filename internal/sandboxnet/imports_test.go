package sandboxnet

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins sandboxnet as the sandbox egress tier's
// network code and nothing else (CLAUDE.md Module Boundaries #1): no database,
// no process spawning (that lives in cmd/observer), no watcher, and no
// internal package but the pure internal/sandboxcidr it re-exports.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden:         []string{"database/sql", "os/exec", "github.com/fsnotify/fsnotify"},
		ForbiddenPrefixes: []string{"github.com/marmutapp/superbased-observer/internal/"},
		Except: []string{
			"github.com/marmutapp/superbased-observer/internal/sandboxcidr",
			// the neutral vocabulary leaf owns the model-provider host set
			// (section 7.3), so the gateway never imports the proxy.
			"github.com/marmutapp/superbased-observer/internal/sandboxvocab",
		},
		Reason: "sandboxnet is network code only",
	})
}
