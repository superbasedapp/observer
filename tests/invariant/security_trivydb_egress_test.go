package invariant

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// security_trivydb_egress_test.go is the dedicated pin of the
// security.scan.trivy.db lane (egress_lanes_test.go; OS and CI
// vulnerability scanning plan section 6.7, lane OS-2 T): the Trivy
// database download, internal/secscan/trivydb, is linked only into the cmd
// layer, never into the daemon's always-on paths (the watcher, the proxy,
// the store, the hook), the dashboard, the pure image driver or the
// shared scanner packages.

var securityTrivyDBLane = "internal/secscan/trivydb"

var securityTrivyDBForbiddenEntries = []string{
	"internal/watcher",
	"internal/proxy",
	"internal/store",
	"internal/hook",
	"internal/hookctx",
	"internal/secsvc",
	"internal/secscan",
	"internal/secscan/trivyimage",
	"internal/secscan/depscan",
	"internal/secscan/osvdb",
	"internal/seciac",
	"internal/intelligence/dashboard",
	"internal/dashapi",
	"internal/orgclient",
}

func TestEgressSecurityTrivyDBNotLinkedByDaemonPaths(t *testing.T) {
	toolchainTest(t)
	root := filepath.Join("..", "..")
	for _, entry := range securityTrivyDBForbiddenEntries {
		t.Run(entry, func(t *testing.T) {
			cmd := exec.Command("go", "list", "-deps", "./"+entry)
			cmd.Dir = root
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("go list -deps ./%s: %v\n%s", entry, err, out)
			}
			self := false
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				rel := strings.TrimPrefix(strings.TrimSpace(line), modulePath)
				if rel == entry {
					self = true
				}
				if rel == securityTrivyDBLane {
					t.Errorf("%s transitively imports %s: the Trivy database lane is linked only into the cmd layer", entry, securityTrivyDBLane)
				}
			}
			if !self {
				t.Fatalf("go list -deps ./%s did not list the package itself; the guard would be vacuous", entry)
			}
		})
	}
}

// TestEgressSecurityTrivyDBImporters: only cmd/observer imports the lane.
func TestEgressSecurityTrivyDBImporters(t *testing.T) {
	toolchainTest(t)
	pkgs := moduleImports(t, "")
	for pkg, imports := range pkgs {
		for _, imp := range imports {
			if imp == modulePath+securityTrivyDBLane && pkg != "cmd/observer" {
				t.Errorf("%s imports %s; only cmd/observer may", pkg, securityTrivyDBLane)
			}
		}
	}
}
