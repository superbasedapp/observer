package landingscan

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/landingscan as orchestration over
// injected funcs (CLAUDE.md rule 1): the read-only git envelope, the
// filesystem stat and every store read and write arrive through Options.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net",
			"net/http",
			"os/exec",
			"github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/store",
			"github.com/marmutapp/superbased-observer/internal/deliverynet",
		},
		Reason: "internal/landingscan must stay I/O-injected and network-free",
	})
}
