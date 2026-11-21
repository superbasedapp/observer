package invariant

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvshard/shardnet"
)

// security_osvshards_egress_test.go is the dedicated pin of the
// security.scan.osv.shards lane (egress_lanes_test.go; OS and CI
// vulnerability scanning plan sections 13.5 and 13.11, lane RM-2): the
// SuperBased package lookup's shard client, internal/secscan/osvshard/
// shardnet, sends project-derived data (which shard digests a node asks
// for follows from its package names' hash prefixes), so it is linked
// only into the cmd layer, never into the daemon's always-on paths (the
// watcher, the proxy, the store, the hook), the dashboard, the shard walk
// itself or the shared scanner packages; and its allow-list is exactly the
// one host the consent text names.

var securityOSVShardsLane = "internal/secscan/osvshard/shardnet"

var securityOSVShardsForbiddenEntries = []string{
	"internal/watcher",
	"internal/proxy",
	"internal/store",
	"internal/hook",
	"internal/hookctx",
	"internal/secsvc",
	"internal/secscan",
	"internal/secscan/depscan",
	"internal/secscan/depdriver",
	"internal/secscan/osvdb",
	"internal/secscan/osvnet",
	"internal/secscan/osvshard",
	"internal/secscan/osvshardkey",
	"internal/intelligence/dashboard",
	"internal/dashapi",
	"internal/orgclient",
	// The org server's mirror store and route (lane RM-3): the shard source
	// is injected, so the lane is linked only where the sync runs.
	"internal/orgserver/secrelay",
	"internal/orgcontract",
}

// securityOSVShardsImporters are the packages that may import the lane: the
// node's cmd layer (lane RM-2, security.scan.osv.shards) and the org
// server's two sync sites (lane RM-3, the server lane org.security.shards:
// the scheduled sync in internal/orgserver, the operator's `observer-org
// security mirror shards sync` in cmd/observer-org).
var securityOSVShardsImporters = map[string]bool{
	"cmd/observer":       true,
	"internal/orgserver": true,
	"cmd/observer-org":   true,
}

func TestEgressSecurityOSVShardsNotLinkedByDaemonPaths(t *testing.T) {
	toolchainTest(t)
	root := filepath.Join("..", "..")
	for _, entry := range securityOSVShardsForbiddenEntries {
		t.Run(entry, func(t *testing.T) {
			// The org server entries (internal/orgserver/secrelay) are
			// private-only: the public tree has no such package to list, so
			// the row skips there and keeps full strength on the private tree.
			if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(entry))); errors.Is(err, fs.ErrNotExist) {
				skipInPublicTree(t, root, entry)
				t.Fatalf("%s is gone: a forbidden entry that no longer exists makes this guard vacuous; drop or rename its row", entry)
			}
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
				if rel == securityOSVShardsLane {
					t.Errorf("%s transitively imports %s: the SuperBased lookup's shard lane is linked only into the cmd layer", entry, securityOSVShardsLane)
				}
			}
			if !self {
				t.Fatalf("go list -deps ./%s did not list the package itself; the guard would be vacuous", entry)
			}
		})
	}
}

// TestEgressSecurityOSVShardsImporters: only the node's cmd layer and the
// org server's two sync sites import the lane.
func TestEgressSecurityOSVShardsImporters(t *testing.T) {
	toolchainTest(t)
	pkgs := moduleImports(t, "")
	for pkg, imports := range pkgs {
		for _, imp := range imports {
			if imp == modulePath+securityOSVShardsLane && !securityOSVShardsImporters[pkg] {
				t.Errorf("%s imports %s; only %v may", pkg, securityOSVShardsLane, securityOSVShardsImporters)
			}
		}
	}
}

// TestEgressSecurityOSVShardsHostAllowList: the lane reaches exactly the
// one host, and the consent the developer accepts names it.
func TestEgressSecurityOSVShardsHostAllowList(t *testing.T) {
	hosts := shardnet.AllowedHosts()
	if len(hosts) != 1 || hosts[0] != "shards.superbased.app" || osvdb.RemoteShardHost != "shards.superbased.app" {
		t.Fatalf("shardnet.AllowedHosts() = %v, want exactly [shards.superbased.app]", hosts)
	}
	if !strings.Contains(osvdb.RemoteConsentText, hosts[0]) {
		t.Fatalf("the remote-lookup consent text does not name %s", hosts[0])
	}
}
