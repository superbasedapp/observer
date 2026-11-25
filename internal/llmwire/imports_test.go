package llmwire

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPureCoreImports pins everything except the transport seam free of
// net/http and SQL.
func TestPureCoreImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Files:     []string{"doc.go", "wire.go", "usage.go", "errors.go", "shape.go"},
		Forbidden: []string{"net/http", "database/sql", "os", "os/exec", "net", "github.com/fsnotify/fsnotify"},
		ForbiddenTrees: []string{
			"github.com/jackc/pgx",
			"github.com/marmutapp/superbased-observer/internal/cloudserver",
			"github.com/marmutapp/superbased-observer/internal/orgserver",
		},
		Reason: "llmwire's wire core is pure; HTTP lives only in transport.go",
	})
}

// TestTransportImports pins the seam: HTTP is allowed, but no SQL and no
// plane package.
func TestTransportImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Files:     []string{"transport.go"},
		Forbidden: []string{"database/sql", "os/exec"},
		ForbiddenTrees: []string{
			"github.com/marmutapp/superbased-observer/internal/cloudserver",
			"github.com/marmutapp/superbased-observer/internal/orgserver",
		},
		Reason: "the transport seam wraps a caller-supplied netguard client and touches no plane",
	})
}
