package spanprice

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestImports keeps the package pure: no SQL, HTTP, fsnotify, and no engine.
func TestImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "net/http", "github.com/fsnotify/fsnotify"},
		ForbiddenPrefixes: []string{
			"github.com/marmutapp/superbased-observer/internal/obs/",
			"github.com/marmutapp/superbased-observer/internal/intelligence",
			"github.com/marmutapp/superbased-observer/internal/orgserver",
		},
		Reason: "spanprice is the pure span pricing rule",
	})
}
