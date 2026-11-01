package sandboxselect

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins selection pure: plain data in, a
// decision out, over the registry and the vocabulary leaf only.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden:  []string{"database/sql", "net/http", "net", "os", "os/exec", "github.com/fsnotify/fsnotify"},
		StdlibOnly: true,
		Allowed: []string{
			"github.com/marmutapp/superbased-observer/internal/sandboxbackend",
			"github.com/marmutapp/superbased-observer/internal/sandboxvocab",
			// the core comparison and merge operators (roadmap F0-8); the
			// posture axes and the evaluator are this package's (posture.go).
			"github.com/marmutapp/superbased-observer/internal/postureop",
		},
		Reason: "selection is a pure decision table",
	})
}
