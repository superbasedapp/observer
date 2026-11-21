package invariant

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// security_dast_egress_test.go is the dedicated pin of the security.dast
// lane (egress_lanes_test.go; OS and CI vulnerability scanning plan sections
// 14.9 and 14.13, phase M3L-5): the local passive DAST checker's dialer,
// internal/secdastnet, is linked only into the cmd layer, never into the
// daemon's always-on paths (the watcher, the proxy, the store, the hook),
// the dashboard, the pure checker or its accept record, and the pure
// checker never links it either: every run starts from the developer's own
// command.

var securityDASTLane = "internal/secdastnet"

var securityDASTForbiddenEntries = []string{
	"internal/watcher",
	"internal/proxy",
	"internal/store",
	"internal/hook",
	"internal/hookctx",
	"internal/secsvc",
	"internal/secscan",
	"internal/secdast",
	"internal/secdast/dastconsent",
	"internal/intelligence/dashboard",
	"internal/dashapi",
	"internal/orgclient",
	"internal/mcp",
}

func TestEgressSecurityDASTNotLinkedByDaemonPaths(t *testing.T) {
	toolchainTest(t)
	root := filepath.Join("..", "..")
	for _, entry := range securityDASTForbiddenEntries {
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
				if rel == securityDASTLane {
					t.Errorf("%s transitively imports %s: the DAST lane is linked only into the cmd layer", entry, securityDASTLane)
				}
			}
			if !self {
				t.Fatalf("go list -deps ./%s did not list the package itself; the guard would be vacuous", entry)
			}
		})
	}
}

// TestEgressSecurityDASTImporters: only cmd/observer imports the lane.
func TestEgressSecurityDASTImporters(t *testing.T) {
	toolchainTest(t)
	pkgs := moduleImports(t, "")
	for pkg, imports := range pkgs {
		for _, imp := range imports {
			if imp == modulePath+securityDASTLane && pkg != "cmd/observer" {
				t.Errorf("%s imports %s; only cmd/observer may", pkg, securityDASTLane)
			}
		}
	}
}
