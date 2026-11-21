package reviewcore

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins reviewcore pure: no I/O, never internal/obs,
// and no project import but the pure score rules.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden:         []string{"database/sql", "net/http", "net", "os", "os/exec", "github.com/fsnotify/fsnotify"},
		ForbiddenTrees:    []string{"github.com/marmutapp/superbased-observer/internal/obs"},
		ForbiddenPrefixes: []string{"github.com/marmutapp/superbased-observer/"},
		Except:            []string{"github.com/marmutapp/superbased-observer/internal/scorecore", "github.com/marmutapp/superbased-observer/internal/genaiattr"},
		Reason:            "internal/reviewcore is the pure review-queue rule set",
	})
}
