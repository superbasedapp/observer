package contentchan

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the content channel's file shell: files only,
// no transport, no storage, no process control.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "net/http", "net", "os/exec", "github.com/fsnotify/fsnotify"},
		Reason:    "internal/contentchan installs verified files; fetching is the caller's",
	})
}
