package scorecore

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins scorecore pure: no I/O and never internal/obs,
// so the machine and the org can both import it.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden:         []string{"database/sql", "net/http", "net", "os", "os/exec", "github.com/fsnotify/fsnotify"},
		ForbiddenTrees:    []string{"github.com/marmutapp/superbased-observer/internal/obs"},
		ForbiddenPrefixes: []string{"github.com/marmutapp/superbased-observer/"},
		Except:            []string{"github.com/marmutapp/superbased-observer/internal/genaiattr"},
		Reason:            "internal/scorecore is the pure score rule set",
	})
}
