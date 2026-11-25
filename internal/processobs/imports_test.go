package processobs

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the boundary doc.go states for this
// OS-independent core: no database/sql, no net/http, no fsnotify and no
// direct /proc reads (no os), with the event source, enricher, seed lookup
// and sink injected by the caller. The OS backends live in their own
// subpackages, which this pin does not scan.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		ForbiddenTrees: []string{
			"database/sql",
			"net/http",
			"os",
			"io/ioutil",
			"github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/store",
			"github.com/marmutapp/superbased-observer/internal/pidbridge",
		},
		Reason: "internal/processobs is pure logic; I/O is injected (doc.go)",
	})
}
