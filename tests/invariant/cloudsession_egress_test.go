package invariant

import (
	"strings"
	"testing"
)

// cloudsession_egress_test.go pins the egress posture of the cloud-session
// feature (Rail S, docs/cloud-sessions.md; cloud-agents plan section 7),
// modelled on planlimits_egress_test.go:
//
//   - internal/cloudsessionnet is the ONLY package of the feature that
//     imports a network or process package (net, net/http, os/exec);
//   - only the observer command imports internal/cloudsessionnet, so the
//     delivery runs only when `observer cloud-session flush` is invoked;
//   - the always-on daemon paths (watcher, proxy, store, hook, the org push
//     client, the adapters the flush scans) never link it, so a node that
//     never runs the flush cannot deliver through it.

// csModulePrefix matches every package of the feature.
const csModulePrefix = "internal/cloudsession"

// csNetPkg is the one package allowed network and process imports.
const csNetPkg = "internal/cloudsessionnet"

// csNetImporters may import csNetPkg.
var csNetImporters = []string{"cmd/observer"}

// csNetworkImports are the imports reserved to csNetPkg.
var csNetworkImports = map[string]bool{"net": true, "net/http": true, "os/exec": true}

func TestCloudSessionNetworkOnlyInOnePackage(t *testing.T) {
	saw := 0
	for _, line := range planGoList(t, "list", "-e", "-f", "{{.ImportPath}}{{range .Imports}} {{.}}{{end}}", "./internal/...") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.HasPrefix(fields[0], modulePath) {
			continue
		}
		rel := strings.TrimPrefix(fields[0], modulePath)
		if !strings.HasPrefix(rel, csModulePrefix) {
			continue
		}
		saw++
		if rel == csNetPkg {
			continue
		}
		for _, imp := range fields[1:] {
			if csNetworkImports[imp] {
				t.Errorf("%s imports %s: only %s may make network calls or run processes for this feature", rel, imp, csNetPkg)
			}
		}
	}
	if saw < 2 {
		t.Fatalf("found %d feature packages, want at least 2: the guard would be vacuous", saw)
	}
}

func TestCloudSessionNetImportersAllowListed(t *testing.T) {
	sawImporter := false
	for _, line := range planGoList(t, "list", "-e", "-f", "{{.ImportPath}}{{range .Imports}} {{.}}{{end}}", "./...") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.HasPrefix(fields[0], modulePath) {
			continue
		}
		importer := strings.TrimPrefix(fields[0], modulePath)
		for _, imp := range fields[1:] {
			if strings.TrimPrefix(imp, modulePath) != csNetPkg {
				continue
			}
			if _, ok := matchesCloudPkg(importer, csNetImporters); ok {
				sawImporter = true
				continue
			}
			t.Errorf("%s imports %s: only the observer command may", importer, csNetPkg)
		}
	}
	if !sawImporter {
		t.Fatal("no allowed importer of the egress package found: the guard would be vacuous")
	}
}

func TestCloudSessionDaemonPathsCannotLinkNet(t *testing.T) {
	for _, entry := range []string{
		"internal/watcher", "internal/proxy", "internal/store", "internal/hook",
		"internal/orgclient", "internal/adapter/claudecode", "internal/adapter/copilotcli",
	} {
		deps := planGoList(t, "list", "-deps", "./"+entry)
		sawSelf := false
		for _, pkg := range deps {
			rel := strings.TrimPrefix(strings.TrimSpace(pkg), modulePath)
			if rel == entry {
				sawSelf = true
			}
			if bad, hit := matchesCloudPkg(rel, []string{csNetPkg}); hit {
				t.Errorf("%s transitively imports %s: the always-on daemon paths must never link the cloud-session egress", entry, bad)
			}
		}
		if !sawSelf {
			t.Fatalf("go list -deps ./%s did not include itself: the guard would be vacuous", entry)
		}
	}
}
