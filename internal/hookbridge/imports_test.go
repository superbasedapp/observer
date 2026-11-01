package hookbridge

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins hookbridge PURE: no process, no file, no
// network, no observer package.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "net", "net/http", "os", "os/exec", "github.com/fsnotify/fsnotify"},
		Custom: func(_, p string) string {
			if strings.HasPrefix(p, "github.com/marmutapp/superbased-observer/") {
				return "no observer package"
			}
			return ""
		},
		Reason: "hookbridge is pure",
	})
}
