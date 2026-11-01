package sandboxbackend

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins the registry pure data: the only
// observer-internal import allowed is the neutral vocabulary leaf.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden:  []string{"database/sql", "net/http", "net", "os", "os/exec", "github.com/fsnotify/fsnotify"},
		StdlibOnly: true,
		Allowed:    []string{"github.com/marmutapp/superbased-observer/internal/sandboxvocab"},
		Reason:     "the backend registry is pure data over the vocabulary leaf",
	})
}
