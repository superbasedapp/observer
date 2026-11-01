package invariant

import (
	"strings"
	"testing"
)

// sandbox_remote_egress_test.go pins the hosted sandbox drivers' egress
// (sandbox plan v2 section 13 P7, ledger row SBX-BE-8, lane SBX-P7):
//
//   - the vendor wire clients (internal/sandboxremote/e2b, /modal, /vercel)
//     are the ONLY sandboxremote packages that import a network package;
//     the shared core and the relay mux are pure;
//   - only cmd/observer imports a vendor client (its per-vendor driver file
//     registers it with the hosted core, which builds a client only in the
//     host helper of a user-launched run and in the leftover-box actions);
//   - the always-on daemon paths (watcher, proxy, store, hook, the
//     adapters) never link a vendor client, so nothing can call a provider
//     without a user action.

// sandboxRemoteClients are the vendor wire clients that exist in this
// build's source tree.
var sandboxRemoteClients = []string{"internal/sandboxremote/e2b", "internal/sandboxremote/modal", "internal/sandboxremote/vercel"}

// sandboxRemotePure are the hosted packages held to no network import.
var sandboxRemotePure = []string{"internal/sandboxremote", "internal/sandboxremote/relaymux"}

// sandboxRemoteDaemonEntries are the always-on paths that must never link a
// vendor client.
var sandboxRemoteDaemonEntries = []string{
	"internal/watcher", "internal/proxy", "internal/store", "internal/hook",
	"internal/adapter/claudecode", "internal/adapter/codex",
}

func TestSandboxRemoteNetworkOnlyInVendorClients(t *testing.T) {
	saw := map[string]bool{}
	for _, line := range deliveryGoList(t, "list", "-e", "-f", "{{.ImportPath}}{{range .Imports}} {{.}}{{end}}", "./internal/sandboxremote/...") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.HasPrefix(fields[0], modulePath) {
			continue
		}
		rel := strings.TrimPrefix(fields[0], modulePath)
		saw[rel] = true
		if contains(sandboxRemoteClients, rel) {
			continue
		}
		for _, imp := range fields[1:] {
			if isNetworkImport(imp) || imp == "os/exec" {
				t.Errorf("%s imports %s: only the vendor clients may reach the network", rel, imp)
			}
		}
	}
	for _, p := range sandboxRemotePure {
		if !saw[p] {
			t.Fatalf("package %s not found: the guard would be vacuous", p)
		}
	}
}

func TestSandboxRemoteClientsImportedOnlyByCmd(t *testing.T) {
	sawImporter := false
	for _, line := range deliveryGoList(t, "list", "-e", "-f", "{{.ImportPath}}{{range .Imports}} {{.}}{{end}}", "./...") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.HasPrefix(fields[0], modulePath) {
			continue
		}
		importer := strings.TrimPrefix(fields[0], modulePath)
		for _, imp := range fields[1:] {
			target := strings.TrimPrefix(imp, modulePath)
			if !contains(sandboxRemoteClients, target) {
				continue
			}
			if importer == "cmd/observer" {
				sawImporter = true
				continue
			}
			t.Errorf("%s imports %s: only cmd/observer may", importer, target)
		}
	}
	if !sawImporter {
		t.Fatal("cmd/observer imports no vendor client: the guard would be vacuous")
	}
}

func TestSandboxRemoteNotLinkedByDaemonPaths(t *testing.T) {
	for _, entry := range sandboxRemoteDaemonEntries {
		deps := deliveryGoList(t, "list", "-deps", "-f", "{{.ImportPath}}", "./"+entry)
		for _, d := range deps {
			rel := strings.TrimPrefix(d, modulePath)
			if contains(sandboxRemoteClients, rel) || rel == "internal/sandboxremote" {
				t.Errorf("%s links %s: an always-on path must never reach a hosted sandbox provider", entry, rel)
			}
		}
	}
}
