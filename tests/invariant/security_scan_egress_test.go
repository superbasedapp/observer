package invariant

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
)

// security_scan_egress_test.go is the dedicated pin of the
// security.scan.osv.db lane (egress_lanes_test.go; security plan sections
// 8.2 and 8.4, ledger SECP-8): the dependency scanners' network client,
// internal/secscan/osvnet, and the SCALIBR facade, which can hand SCALIBR
// an HTTP client, are linked only into the daemon's scan loop and the
// `observer security scan` command (cmd/observer), never into the
// always-on daemon paths, the hook, the install gate or the scan child's
// pure cores.

var securityScanLanePackages = []string{"internal/secscan/osvnet", "internal/secscan/scalibrfacade"}

var securityScanForbiddenEntries = []string{
	"internal/watcher",
	"internal/proxy",
	"internal/store",
	"internal/hook",
	"internal/hookctx",
	"internal/secfeed",
	"internal/secask",
	"internal/secrules",
	"internal/secverify",
	"internal/secsvc",
	"internal/secscan",
	"internal/secscan/depscan",
	"internal/secscan/osvdb",
	"internal/orgclient",
}

func TestEgressSecurityScanNotLinkedByDaemonPaths(t *testing.T) {
	toolchainTest(t)
	root := filepath.Join("..", "..")
	for _, entry := range securityScanForbiddenEntries {
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
				for _, lane := range securityScanLanePackages {
					if rel == lane {
						t.Errorf("%s transitively imports %s: the scan lane is linked only into the scan loop and command", entry, lane)
					}
				}
			}
			if !self {
				t.Fatalf("go list -deps ./%s did not list the package itself; the guard would be vacuous", entry)
			}
		})
	}
}

// TestEgressSecurityScanImporters: osvnet is imported only by cmd/observer;
// the facade only by cmd/observer and the scan child.
func TestEgressSecurityScanImporters(t *testing.T) {
	toolchainTest(t)
	allowed := map[string]map[string]bool{
		"internal/secscan/osvnet":        {"cmd/observer": true},
		"internal/secscan/scalibrfacade": {"cmd/observer": true, "internal/secscan/scalibrchild": true},
	}
	pkgs := moduleImports(t, "")
	for rel, imps := range pkgs {
		if strings.HasSuffix(rel, "_test") {
			continue
		}
		for _, imp := range imps {
			lane := strings.TrimPrefix(imp, modulePath)
			ok, isLane := allowed[lane]
			if isLane && !ok[rel] {
				t.Errorf("%s imports %s; only %v may", rel, lane, ok)
			}
		}
	}
}

// TestEgressSecurityScanBucketDeclared pins milestone 1d of lane SEC-D2B:
// both dependency drivers read the OSV database Observer downloads, so the
// bucket is declared on both catalog rows and both registry rows, not only
// on the SCALIBR child.
func TestEgressSecurityScanBucketDeclared(t *testing.T) {
	const bucket = "osv-vulnerabilities.storage.googleapis.com"
	for _, row := range []secscan.DriverRow{depscan.ScalibrRow(nil), depscan.OSVRow()} {
		found := false
		for _, e := range row.Egress {
			found = found || e.Host == bucket
		}
		if !found {
			t.Errorf("driver row %s does not declare %s", row.ID, bucket)
		}
		c, ok := components.Get(row.ComponentID)
		if !ok {
			t.Fatalf("no catalog row %s", row.ComponentID)
		}
		found = false
		for _, e := range c.Surface.Egress {
			found = found || e.Host == bucket
		}
		if !found {
			t.Errorf("catalog row %s does not declare %s", row.ComponentID, bucket)
		}
	}
}
