package invariant

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// pricing_feed_egress_test.go pins the egress isolation of the standalone-node
// pricing feed's NETWORK LANE (internal/pricingfeed/client), the sibling of
// cloud_egress_test.go's TestCloudClientIsolatedToConsentGateway.
//
// The posture (plan §C.3 / §F; D3 SUPERSEDED 2026-09-20): the standalone-node
// feed is now ON by default, so an individual node DOES fetch prices unless the
// operator opts out (`[pricing.feed] enabled = false`). What this test still
// pins is the STRUCTURAL egress isolation, which is unchanged by that flip: the
// one outbound path is reachable only through internal/pricingfeedgate (the seam
// cmd/observer composes, driven by the manual CLI + the opt-in autosync
// tickers); the always-on daemon packages and the org push loop must never even
// LINK the network lane. Proving that structurally — a package that cannot
// import the lane cannot egress through it — is stronger than any runtime
// assertion, and holds regardless of the default-enabled flag.
//
// NOTE the PARENT package internal/pricingfeed (the pure contract + verify +
// canonical body + vendor key) is deliberately NOT isolated: it is imported
// freely (the org importer, the store cache, the gate all need the types). Only
// the /client SUBPACKAGE, which holds the *http.Client, is pinned here.

// pricingFeedNetworkPackage is the network/transport package the daemon must
// never link. Matched as the package OR any subpackage.
const pricingFeedNetworkPackage = "internal/pricingfeed/client"

// pricingFeedDaemonEntryPackages are the always-on daemon surfaces plus the org
// push loop (plan §C.3 / §F). None may TRANSITIVELY import the network lane.
var pricingFeedDaemonEntryPackages = []string{
	"internal/watcher",
	"internal/proxy",
	"internal/store",
	"internal/hook",
	"internal/orgclient",
}

// pricingFeedClientAllowedImporterPrefixes is the set permitted to import the
// network lane. The ONLY node-side importer is internal/pricingfeedgate — the
// egress seam — plus the lane itself. Extend this ONLY with a package that is
// the one auditable egress point; adding a caller here to skip the gate would
// re-open exactly the hole the seam closes.
var pricingFeedClientAllowedImporterPrefixes = []string{
	"internal/pricingfeedgate",
	"internal/pricingfeed/client",
}

// TestPricingFeedDaemonPathsCannotReachClient is the PRIMARY zero-egress guard:
// the full transitive dependency closure of each always-on daemon package (and
// the org push loop) must contain NONE of the network lane.
func TestPricingFeedDaemonPathsCannotReachClient(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	for _, entry := range pricingFeedDaemonEntryPackages {
		entry := entry
		t.Run(entry, func(t *testing.T) {
			cmd := exec.Command("go", "list", "-deps", "./"+entry)
			cmd.Dir = repoRoot
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("go list -deps ./%s failed: %v\n%s", entry, err, out)
			}
			var sawSelf bool
			var count int
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				pkg := strings.TrimSpace(line)
				if !strings.HasPrefix(pkg, modulePath) {
					continue
				}
				count++
				rel := strings.TrimPrefix(pkg, modulePath)
				if rel == entry {
					sawSelf = true
				}
				if rel == pricingFeedNetworkPackage || strings.HasPrefix(rel, pricingFeedNetworkPackage+"/") {
					t.Errorf("daemon package %q transitively imports %q — the always-on daemon paths "+
						"and the org push loop must never reach the pricing-feed network lane (plan §C.3/§F "+
						"zero-egress; reach it only through internal/pricingfeedgate)", entry, pricingFeedNetworkPackage)
				}
			}
			if count == 0 || !sawSelf {
				t.Fatalf("go list -deps ./%s returned an unexpectedly empty/self-less module closure "+
					"(count=%d sawSelf=%v) — the guard would be vacuous", entry, count, sawSelf)
			}
		})
	}
}

// TestPricingFeedClientIsolatedToGate is the isolation guard: no package in the
// module may import the network lane EXCEPT the gate (and the lane itself).
// Uses DIRECT imports so a package's own tests importing the lane are not
// flagged — what must not exist is a PRODUCTION path that reaches the network
// without the gate.
func TestPricingFeedClientIsolatedToGate(t *testing.T) {
	repoRoot := filepath.Join("..", "..")
	cmd := exec.Command("go", "list", "-e", "-f", "{{.ImportPath}}{{range .Imports}} {{.}}{{end}}", "./...")
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list ./... failed: %v\n%s", err, out)
	}
	allowed := func(importerRel string) bool {
		for _, p := range pricingFeedClientAllowedImporterPrefixes {
			if importerRel == p || strings.HasPrefix(importerRel, p+"/") {
				return true
			}
		}
		return false
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 {
			continue
		}
		importer := fields[0]
		if !strings.HasPrefix(importer, modulePath) {
			continue
		}
		importerRel := strings.TrimPrefix(importer, modulePath)
		for _, imp := range fields[1:] {
			if !strings.HasPrefix(imp, modulePath) {
				continue
			}
			impRel := strings.TrimPrefix(imp, modulePath)
			if impRel != pricingFeedNetworkPackage && !strings.HasPrefix(impRel, pricingFeedNetworkPackage+"/") {
				continue
			}
			if allowed(importerRel) {
				continue
			}
			t.Errorf("package %q imports pricing-feed network lane %q — only internal/pricingfeedgate "+
				"(the egress seam) and the lane itself may import it (plan §C.3/§F). Compose "+
				"internal/pricingfeedgate instead; if this really is a new legitimate importer, extend "+
				"pricingFeedClientAllowedImporterPrefixes deliberately.", importerRel, pricingFeedNetworkPackage)
		}
	}
}
