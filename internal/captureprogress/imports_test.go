package captureprogress

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/captureprogress pure (CLAUDE.md
// section 1): the watcher feeds it and the dashboard reads it; it never
// reaches a database, HTTP, the filesystem or fsnotify itself.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net/http",
			"os",
			"io/fs",
			"path/filepath",
			"github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/store",
			"github.com/marmutapp/superbased-observer/internal/watcher",
		},
		Reason: "internal/captureprogress must stay pure",
	})
}
