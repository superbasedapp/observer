package routingcore

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins routingcore pure, as its doc.go claims (no
// I/O, no DB, no HTTP, no filesystem), with the same boundary as
// internal/routing's pin (CLAUDE.md Module Boundaries, spec section 24.1,
// model-routing spec section R5) plus the os and os/exec packages.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"os",
			"os/exec",
		},
		ForbiddenTrees: []string{
			"database/sql",
			"net/http",
			"github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/store",
			"github.com/marmutapp/superbased-observer/internal/proxy",
			"github.com/marmutapp/superbased-observer/internal/db",
			"github.com/marmutapp/superbased-observer/internal/adapter",
			"github.com/marmutapp/superbased-observer/internal/watcher",
			"github.com/marmutapp/superbased-observer/internal/hook",
			"github.com/marmutapp/superbased-observer/internal/intelligence",
			"github.com/marmutapp/superbased-observer/internal/mcp",
			"github.com/marmutapp/superbased-observer/internal/config",
			"github.com/marmutapp/superbased-observer/internal/freshness",
			"github.com/marmutapp/superbased-observer/internal/scoring",
			"github.com/marmutapp/superbased-observer/internal/compression",
			"github.com/marmutapp/superbased-observer/internal/routing",
		},
		Reason: "routingcore is pure logic (doc.go): module boundary section 24.1 / section R5",
	})
}
