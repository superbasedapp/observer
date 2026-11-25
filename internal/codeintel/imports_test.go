package codeintel_test

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPureSubpackageImports_Bounded walks every non-test .go file under the
// pure codeintel subpackages (recursively, plan 3.1). The I/O-bearing index and
// surface packages and the facade root are the seams and are excluded.
func TestPureSubpackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Dirs: []string{
			"parse",
			"resolve",
			"semantic",
			"analyze",
			"query",
		},
		Recursive: true,
		ForbiddenTrees: []string{
			"database/sql",
			"net/http",
			"github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/store",
			"github.com/marmutapp/superbased-observer/internal/db",
			"github.com/marmutapp/superbased-observer/internal/proxy",
			"github.com/marmutapp/superbased-observer/internal/adapter",
			"github.com/marmutapp/superbased-observer/internal/watcher",
			"github.com/marmutapp/superbased-observer/internal/hook",
			"github.com/marmutapp/superbased-observer/internal/mcp",
			"github.com/marmutapp/superbased-observer/internal/config",
			"github.com/marmutapp/superbased-observer/internal/compression",
		},
		Reason: "codeintel pure-core boundary, plan 3.1",
	})
}
