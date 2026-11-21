package orgdeletion

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestBoundaryImports pins orgdeletion as a pure core: no SQL, no HTTP, no
// file watching; the store, the journal and the billing and identity seams
// are injected.
func TestBoundaryImports(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		AllowOnly: true,
		Allowed: []string{
			"context", "errors", "fmt", "regexp", "slices", "time",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/deletionjournal",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi",
			"github.com/marmutapp/superbased-observer/internal/platformcontract",
		},
		Reason: "orgdeletion is the pure deletion core; SQL lives in internal/cloudserver/store, I/O in the worker",
	})
}
