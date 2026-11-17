package cvss4

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Pure pins cvss4 to the standard library and to string
// and float work (CLAUDE.md module rule 1): no database, network, subprocess,
// filesystem, file watcher or other observer package. The generated tables
// and the scorer are pure data and arithmetic; the oracle tests read their
// fixtures, but only from _test.go files, which this pin does not scan.
func TestPackageImports_Pure(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		StdlibOnly: true,
		Forbidden: []string{
			"database/sql", "net", "net/http", "net/http/httptest", "crypto/tls", "os", "os/exec",
			"io/ioutil", "io/fs", "syscall", "github.com/fsnotify/fsnotify",
		},
		ForbiddenPrefixes: []string{"github.com/marmutapp/superbased-observer/"},
		Reason:            "cvss4 scores a vector from generated tables; it reads and writes nothing",
	})
}
