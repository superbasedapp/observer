package netlanes

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the package pure (doc.go): data and
// formatting only, no network, file system, config or store.
func TestNoForbiddenImports(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		StdlibOnly: true,
		Forbidden: []string{
			"database/sql", "net", "net/http", "os", "os/exec", "github.com/fsnotify/fsnotify",
		},
		Reason: "internal/netlanes is the pure user-facing lane list",
	})
}
