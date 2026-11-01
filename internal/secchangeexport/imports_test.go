package secchangeexport

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports keeps the export adapters pure: the cmd layer
// reads git and the store and writes the output.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"os", "os/exec", "net", "net/http", "database/sql", "github.com/fsnotify/fsnotify"},
		Reason:    "keep internal/secchangeexport pure",
	})
}
