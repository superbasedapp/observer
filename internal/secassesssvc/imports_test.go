package secassesssvc

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports pins the service to the standard library, the pure core
// and the atomic file writer: no HTTP, no database, no dashboard or store, no
// security component package and no keystore or cloud credential package (the
// module never reads or stores a cloud credential), no subprocess.
func TestPackageImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "net", "net/http", "os/exec", "github.com/fsnotify/fsnotify"},
		ForbiddenPrefixes: []string{
			"github.com/marmutapp/superbased-observer/",
		},
		Except: []string{
			"github.com/marmutapp/superbased-observer/internal/secassess",
			"github.com/marmutapp/superbased-observer/internal/fsatomic",
		},
		Reason: "secassesssvc is the module's I/O over plain values; the dashboard owns HTTP and the seams",
	})
}
