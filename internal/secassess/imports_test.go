package secassess

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Pure pins secassess to string and table work (CLAUDE.md
// module rule 1): no database, network, subprocess, filesystem, file watcher
// or other observer package. In particular it imports nothing from the
// security component (internal/secfinding, internal/secscan) or from
// security.dast (internal/secdast), so the component fence and the omit
// builds are untouched (plan section 10).
func TestPackageImports_Pure(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql", "net", "net/http", "net/http/httptest", "crypto/tls", "os", "os/exec",
			"io/ioutil", "io/fs", "syscall", "github.com/fsnotify/fsnotify",
		},
		ForbiddenPrefixes: []string{"github.com/marmutapp/superbased-observer/"},
		// The CVSS 4.0 scorer is a pure subpackage of this one (W7.1).
		Except: []string{"github.com/marmutapp/superbased-observer/internal/secassess/cvss4"},
		Reason: "secassess decides and renders; secassesssvc reads and writes",
	})
}
