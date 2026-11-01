package invariant

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// delivery_egress_test.go pins the commit to PR to merge tracking arc's
// egress posture (docs/plans/commit-pr-merge-tracking-plan-2026-10-15.md
// section 7.2; ledger rows DELIV-1 and DELIV-3):
//
//   - internal/deliverynet is the ONLY delivery package that imports a
//     network or process package (net, net/http, os/exec);
//   - only internal/deliverysvc and cmd/observer import internal/deliverynet;
//   - the always-on daemon paths (watcher, proxy, store, hook, adapters, the
//     commit scanner and the local landing scan) never link deliverynet or
//     deliverysvc, so a node that never connected a code host or opted into
//     a mirror cannot call out for this feature.

// deliveryNetPkg is the one delivery package allowed network and process
// imports.
const deliveryNetPkg = "internal/deliverynet"

// deliveryPkgs are the delivery packages held to the no-network rule.
var deliveryPkgs = []string{"internal/delivery", "internal/deliverynet", "internal/deliverysvc"}

// deliveryNetImporters may import deliveryNetPkg.
var deliveryNetImporters = []string{"internal/deliverysvc", "cmd/observer"}

// deliveryNetworkImports are the imports reserved to deliveryNetPkg.
var deliveryNetworkImports = map[string]bool{"net": true, "net/http": true, "os/exec": true}

// deliveryLocalScanNetworkImports are forbidden in the local landing scan
// (it reads git through internal/gitview and never reaches the network).
var deliveryLocalScanNetworkImports = map[string]bool{"net": true, "net/http": true}

// deliveryDaemonEntries are the always-on paths that must never link the
// delivery egress.
var deliveryDaemonEntries = []string{
	"internal/watcher", "internal/proxy", "internal/store", "internal/hook",
	"internal/adapter/claudecode", "internal/adapter/codex",
	"internal/commitscan", "internal/landingscan",
}

func deliveryGoList(t *testing.T, args ...string) []string {
	t.Helper()
	toolchainTest(t)
	cmd := exec.Command("go", args...)
	cmd.Dir = filepath.Join("..", "..")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go %v: %v\n%s", args, err, out)
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n")
}

func TestDeliveryEgressNetworkOnlyInDeliverynet(t *testing.T) {
	saw := map[string]bool{}
	for _, line := range deliveryGoList(t, "list", "-e", "-f", "{{.ImportPath}}{{range .Imports}} {{.}}{{end}}", "./internal/...") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.HasPrefix(fields[0], modulePath) {
			continue
		}
		rel := strings.TrimPrefix(fields[0], modulePath)
		forbidden := deliveryNetworkImports
		switch {
		case rel == "internal/landingscan" || strings.HasPrefix(rel, "internal/landingscan/"):
			forbidden = deliveryLocalScanNetworkImports
		case contains(deliveryPkgs, rel):
		default:
			continue
		}
		saw[rel] = true
		if rel == deliveryNetPkg {
			continue
		}
		for _, imp := range fields[1:] {
			if forbidden[imp] {
				t.Errorf("%s imports %s: only %s may make network calls or run processes for the delivery feature", rel, imp, deliveryNetPkg)
			}
		}
	}
	for _, p := range deliveryPkgs {
		if !saw[p] {
			t.Fatalf("package %s not found: the guard would be vacuous", p)
		}
	}
}

func TestDeliveryEgressImportersAllowListed(t *testing.T) {
	sawImporter := false
	for _, line := range deliveryGoList(t, "list", "-e", "-f", "{{.ImportPath}}{{range .Imports}} {{.}}{{end}}", "./...") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.HasPrefix(fields[0], modulePath) {
			continue
		}
		importer := strings.TrimPrefix(fields[0], modulePath)
		for _, imp := range fields[1:] {
			target := strings.TrimPrefix(imp, modulePath)
			if _, hit := matchesCloudPkg(target, []string{deliveryNetPkg}); !hit {
				continue
			}
			if _, ok := matchesCloudPkg(importer, []string{deliveryNetPkg}); ok {
				continue
			}
			if _, ok := matchesCloudPkg(importer, deliveryNetImporters); ok {
				sawImporter = true
				continue
			}
			t.Errorf("%s imports %s: only internal/deliverysvc and cmd/observer may", importer, target)
		}
	}
	if !sawImporter {
		t.Fatalf("no allowed importer of %s found: the guard would be vacuous", deliveryNetPkg)
	}
}

func TestDeliveryEgressDaemonPathsCannotLink(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, entry := range deliveryDaemonEntries {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(entry))); err != nil {
			// A package that does not exist yet links nothing; the
			// non-vacuous checks below cover the ones that do.
			continue
		}
		deps := deliveryGoList(t, "list", "-deps", "./"+entry)
		sawSelf := false
		for _, pkg := range deps {
			rel := strings.TrimPrefix(strings.TrimSpace(pkg), modulePath)
			if rel == entry {
				sawSelf = true
			}
			if bad, hit := matchesCloudPkg(rel, []string{deliveryNetPkg, "internal/deliverysvc"}); hit {
				t.Errorf("%s transitively imports %s: the always-on daemon paths must never link the delivery egress", entry, bad)
			}
		}
		if !sawSelf {
			t.Fatalf("go list -deps ./%s did not include itself: the guard would be vacuous", entry)
		}
	}
}
