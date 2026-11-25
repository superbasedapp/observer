package messagesummary

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_NoDatabase pins that messagesummary writes no SQL: the
// summary_calls row reaches the store's InsertSummaryCall seam through the
// CallRowWriter cmd/observer injects (CLAUDE.md rule 4, one owner per table).
func TestPackageImports_NoDatabase(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		ForbiddenTrees: []string{
			"database/sql",
			"github.com/marmutapp/superbased-observer/internal/store",
			"github.com/marmutapp/superbased-observer/internal/db",
		},
		Reason: "summary_calls is written through store.InsertSummaryCall, injected as a CallRowWriter",
	})
}
