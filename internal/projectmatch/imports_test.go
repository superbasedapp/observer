package projectmatch

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the module boundary (CLAUDE.md rule 1).
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "net/http", "os/exec", "github.com/fsnotify/fsnotify", "github.com/marmutapp/superbased-observer/internal/store"},
		Reason:    "internal/projectmatch must stay pure",
	})
}
