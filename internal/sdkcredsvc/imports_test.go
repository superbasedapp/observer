package sdkcredsvc

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports keeps the machine's SDK key service off the network and the database: it reaches the org only through the injected client, and the key file only through internal/keystore.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden:      []string{"database/sql", "net/http", "github.com/fsnotify/fsnotify", "os/exec"},
		ForbiddenTrees: []string{"github.com/marmutapp/superbased-observer/internal/obs", "github.com/marmutapp/superbased-observer/internal/orgserver"},
		Reason:         "internal/sdkcredsvc is the machine's SDK key service (D18)",
	})
}
