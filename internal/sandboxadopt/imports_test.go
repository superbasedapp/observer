package sandboxadopt

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins the re-adoption decisions pure (CLAUDE.md
// Module Boundaries #1): the engine, the records and the terminal are the
// caller's.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden:  []string{"database/sql", "net/http", "net", "os", "os/exec", "syscall", "github.com/fsnotify/fsnotify"},
		StdlibOnly: true,
		Reason:     "the re-adoption and checkpoint decisions are pure; every fact is read by the caller",
	})
}
