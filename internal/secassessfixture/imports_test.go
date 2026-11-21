package secassessfixture

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Pure pins the non-test code of secassessfixture to
// string, JSON and table work (CLAUDE.md module rule 1): no database,
// network, subprocess, filesystem or other observer package. The tests of the
// package read files and, only with OBSERVER_SECASSESS_FIXTURE=1, start the
// application; the pin scans the non-test files only.
func TestPackageImports_Pure(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql", "net", "net/http", "net/http/httptest", "crypto/tls", "os", "os/exec",
			"io/ioutil", "io/fs", "syscall", "github.com/fsnotify/fsnotify",
		},
		ForbiddenPrefixes: []string{"github.com/marmutapp/superbased-observer/"},
		Reason:            "secassessfixture decodes the answer key; the tests read and run",
	})
}
