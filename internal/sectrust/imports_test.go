package sectrust

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// osAdapterFile is the single file allowed to touch the real filesystem.
const osAdapterFile = "fs_os.go"

// TestNoForbiddenImports pins internal/sectrust pure: no database, network,
// process or watcher package, no store, and os and path/filepath only in
// the one adapter file.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net/http",
			"net",
			"os/exec",
			"github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/store",
			"github.com/marmutapp/superbased-observer/internal/db",
			"github.com/marmutapp/superbased-observer/internal/extrun",
		},
		Custom: func(file, p string) string {
			if filepath.Base(file) != osAdapterFile && (p == "os" || p == "path/filepath") {
				return "filesystem access belongs in " + osAdapterFile + ", reached through the FS seam"
			}
			return ""
		},
		Reason: "internal/sectrust must stay pure",
	})
	if _, err := os.Stat(osAdapterFile); err != nil {
		t.Fatalf("%s is missing: the adapter-only allowance points at nothing", osAdapterFile)
	}
}
