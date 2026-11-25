package mcpsec

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the boundary doc.go states and the code keeps
// today: no SQL, no HTTP, no fsnotify, no subprocess (the package never runs
// a server to ask for its tools) and no store (the cmd layer sequences the
// I/O).
//
// doc.go also says the package does no os.ReadFile on its own initiative,
// but Inventory falls back to os.ReadFile when it is handed a nil read
// function, so the package imports "os" today. The pin does not forbid "os"
// until that mismatch has a ruling (maintainability audit 2026-11-22,
// SEC-15).
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		ForbiddenTrees: []string{
			"database/sql",
			"net/http",
			"os/exec",
			"io/ioutil",
			"github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/store",
		},
		Reason: "internal/guard/mcpsec is pure logic (doc.go); I/O lives in the cmd layer",
	})
}
