package invariant

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
)

// cloudagents_egress_test.go pins the node cloud-agent pull connectors'
// egress posture (docs/plans/cloud-agents/cloud-agents-implementation-plan-2026-10-31.md
// section 5.1, decision CA-D5; docs/cloud-agents.md; ledger row CLOUDAGENTS-1
// in docs/security.md):
//
//   - internal/cloudagentsnet is the ONLY package of the feature that imports
//     a network or process package (net, net/http, os/exec); the pure core
//     internal/cloudagents and the service internal/cloudagentssvc import
//     none;
//   - only internal/cloudagentssvc and cmd/observer import cloudagentsnet;
//   - the always-on daemon paths (watcher, proxy, store, hook, every adapter)
//     never link cloudagentsnet or cloudagentssvc, and the dashboard reaches
//     the service but never links the egress, so a node with no linked
//     account cannot call out for this feature from any of them. The service
//     itself makes no vendor call with no linked account
//     (internal/cloudagentssvc TestNoAccountsMeansNoEgress).

const cloudAgentsNetPkg = "internal/cloudagentsnet"

// cloudAgentsPkgs are the feature's packages held to the no-network rule.
var cloudAgentsPkgs = []string{"internal/cloudagents", "internal/cloudagentsnet", "internal/cloudagentssvc"}

// cloudAgentsNetImporters may import cloudAgentsNetPkg.
var cloudAgentsNetImporters = []string{"internal/cloudagentssvc", "cmd/observer"}

// cloudAgentsNetworkImports are reserved to cloudAgentsNetPkg.
var cloudAgentsNetworkImports = map[string]bool{"net": true, "net/http": true, "os/exec": true}

// cloudAgentsDaemonEntries must never link the egress or the service.
var cloudAgentsDaemonEntries = []string{
	"internal/watcher", "internal/proxy", "internal/store", "internal/hook",
	"internal/adapter/claudecode", "internal/adapter/codex", "internal/adapter/copilot",
	"internal/adapter/copilotcli", "internal/adapter/cursor",
}

// cloudAgentsNoEgressEntries may link the service but never the egress.
var cloudAgentsNoEgressEntries = []string{"internal/intelligence/dashboard", "internal/dashapi"}

func TestCloudAgentsNetworkOnlyInNetPackage(t *testing.T) {
	saw := map[string]bool{}
	for _, line := range deliveryGoList(t, "list", "-e", "-f", "{{.ImportPath}}{{range .Imports}} {{.}}{{end}}", "./internal/...") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.HasPrefix(fields[0], modulePath) {
			continue
		}
		rel := strings.TrimPrefix(fields[0], modulePath)
		if !contains(cloudAgentsPkgs, rel) {
			continue
		}
		saw[rel] = true
		if rel == cloudAgentsNetPkg {
			continue
		}
		for _, imp := range fields[1:] {
			if cloudAgentsNetworkImports[imp] {
				t.Errorf("%s imports %s: only %s may make network calls or run processes for the cloud-agent connectors", rel, imp, cloudAgentsNetPkg)
			}
		}
	}
	for _, p := range cloudAgentsPkgs {
		if !saw[p] {
			t.Fatalf("package %s not found: the guard would be vacuous", p)
		}
	}
}

func TestCloudAgentsNetImportersAllowListed(t *testing.T) {
	sawImporter := false
	for _, line := range deliveryGoList(t, "list", "-e", "-f", "{{.ImportPath}}{{range .Imports}} {{.}}{{end}}", "./...") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.HasPrefix(fields[0], modulePath) {
			continue
		}
		importer := strings.TrimPrefix(fields[0], modulePath)
		for _, imp := range fields[1:] {
			target := strings.TrimPrefix(imp, modulePath)
			if _, hit := matchesCloudPkg(target, []string{cloudAgentsNetPkg}); !hit {
				continue
			}
			if _, ok := matchesCloudPkg(importer, []string{cloudAgentsNetPkg}); ok {
				continue
			}
			if _, ok := matchesCloudPkg(importer, cloudAgentsNetImporters); ok {
				sawImporter = true
				continue
			}
			t.Errorf("%s imports %s: only internal/cloudagentssvc and cmd/observer may", importer, target)
		}
	}
	if !sawImporter {
		t.Fatalf("no allowed importer of %s found: the guard would be vacuous", cloudAgentsNetPkg)
	}
}

func TestCloudAgentsDaemonPathsCannotLink(t *testing.T) {
	root := filepath.Join("..", "..")
	check := func(entry string, forbidden []string) {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(entry))); err != nil {
			t.Fatalf("entry %s does not exist: the guard would be vacuous", entry)
		}
		sawSelf := false
		for _, pkg := range deliveryGoList(t, "list", "-deps", "./"+entry) {
			rel := strings.TrimPrefix(strings.TrimSpace(pkg), modulePath)
			if rel == entry {
				sawSelf = true
			}
			if bad, hit := matchesCloudPkg(rel, forbidden); hit {
				t.Errorf("%s transitively imports %s", entry, bad)
			}
		}
		if !sawSelf {
			t.Fatalf("go list -deps ./%s did not include itself: the guard would be vacuous", entry)
		}
	}
	for _, entry := range cloudAgentsDaemonEntries {
		check(entry, []string{cloudAgentsNetPkg, "internal/cloudagentssvc"})
	}
	for _, entry := range cloudAgentsNoEgressEntries {
		check(entry, []string{cloudAgentsNetPkg})
	}
}

// cloudAgentsAPIHosts is the reviewed host table of the API connectors (lane
// CA-B2; ledger row CLOUDAGENTS-3). A new host is a reviewed change here, in
// the egress lane row and in docs/security.md, never a silent table edit.
// Lane CA-V1 adds app.warp.dev (the Warp Agent API, ledger CLOUDAGENTS-WARP-1);
// lane CA-V2 adds Qoder's two region hosts (one picked per account); lane
// CA-V6 adds api.cline.bot (ledger CLINECLOUD-1).
var cloudAgentsAPIHosts = []string{"api.cline.bot", "api.cursor.com", "api.devin.ai", "api.qoder.com", "api.qoder.com.cn", "app.all-hands.dev", "app.warp.dev"}

func TestCloudAgentsAPIHostsPinned(t *testing.T) {
	var got []string
	for _, c := range cloudagents.Connectors {
		if c.Kind != cloudagents.SourceAPI {
			if len(c.APIHosts) != 0 {
				t.Errorf("%s: a CLI connector declares HTTPS hosts", c.ID)
			}
			continue
		}
		got = append(got, c.APIHosts...)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(cloudAgentsAPIHosts, ",") {
		t.Fatalf("API connector hosts = %v, want the reviewed %v", got, cloudAgentsAPIHosts)
	}
	ops := cloudagents.APIOps()
	if len(ops) == 0 {
		t.Fatal("no API request shapes: the guard would be vacuous")
	}
	for _, r := range ops {
		rest, ok := strings.CutPrefix(r.URL, "https://")
		host, _, _ := strings.Cut(rest, "/")
		c, _ := cloudagents.ConnectorByID(r.Connector)
		// A row with a region table sends a request to its account's region
		// host, which must be in that table; every other row has one host.
		own := len(c.APIHosts) > 0 && host == c.APIHosts[0]
		for _, rg := range c.Regions {
			own = own || host == rg.Host
		}
		if !ok || !own {
			t.Errorf("%s %s: %s is not on the row's own https host", r.Connector, r.Op, r.URL)
		}
		if strings.ContainsAny(r.URL, "@#") {
			t.Errorf("%s %s: URL carries user info or a fragment", r.Connector, r.Op)
		}
	}
}
