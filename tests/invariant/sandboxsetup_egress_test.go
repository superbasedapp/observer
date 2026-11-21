package invariant

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// sandboxsetup_egress_test.go is the dedicated pin of the sandbox.setup.net
// lane (egress_lanes_test.go; sandbox installation lifecycle plan section 8,
// ledger SBXSETUP-2 and SHR-3), in the style of cloud_egress_test.go: sandbox
// setup's network client, internal/sandboxsetupnet (the pinned download of a
// sandbox host tool's vendor release asset), is linked only into the cmd
// layer, where the setup runner reaches it on a person's click or
// `observer sandbox setup run`. The always-on daemon paths (watcher, proxy,
// store, hook), the pure setup planner, the sandbox drivers and the
// dashboard's route layer never link it, so no timer, daemon start, org push
// or config change can start a download.

var sandboxSetupNetLane = "internal/sandboxsetupnet"

var sandboxSetupNetForbiddenEntries = []string{
	"internal/watcher",
	"internal/proxy",
	"internal/store",
	"internal/hook",
	"internal/hookctx",
	"internal/orgclient",
	"internal/sandboxsetup",
	"internal/sandboxselect",
	"internal/sandboxbackend",
	"internal/sandboxvm",
	"internal/toolinstall",
	"internal/termsvc",
	"internal/dashapi",
	"internal/intelligence/dashboard",
}

// TestEgressSandboxSetupNotLinkedByDaemonPaths: none of the always-on or
// pure entries transitively imports the lane.
func TestEgressSandboxSetupNotLinkedByDaemonPaths(t *testing.T) {
	toolchainTest(t)
	root := filepath.Join("..", "..")
	for _, entry := range sandboxSetupNetForbiddenEntries {
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
				if rel == sandboxSetupNetLane {
					t.Errorf("%s transitively imports %s: sandbox setup's download lane is linked only into the cmd layer", entry, sandboxSetupNetLane)
				}
			}
			if !self {
				t.Fatalf("go list -deps ./%s did not list the package itself; the guard would be vacuous", entry)
			}
		})
	}
}

// TestEgressSandboxSetupImporters: only cmd/observer imports the lane, and it
// does (so the lane row in egress_lanes_test.go is live, not planned).
func TestEgressSandboxSetupImporters(t *testing.T) {
	toolchainTest(t)
	pkgs := moduleImports(t, "")
	importedByCmd := false
	for pkg, imports := range pkgs {
		for _, imp := range imports {
			if imp != modulePath+sandboxSetupNetLane {
				continue
			}
			if pkg != "cmd/observer" {
				t.Errorf("%s imports %s; only cmd/observer may", pkg, sandboxSetupNetLane)
			}
			importedByCmd = true
		}
	}
	if !importedByCmd {
		t.Errorf("cmd/observer does not import %s; the guard would be vacuous", sandboxSetupNetLane)
	}
}

// TestEgressSandboxSetupAbsentWithoutTheModule: a build without the sandbox
// module (sbo_omit_terminals_sandbox) does not link the lane at all.
func TestEgressSandboxSetupAbsentWithoutTheModule(t *testing.T) {
	toolchainTest(t)
	for _, tags := range []string{"sbo_omit_terminals_sandbox", "sbo_omit_terminals"} {
		t.Run(tags, func(t *testing.T) {
			cmd := exec.Command("go", "list", "-deps", "-tags", tags, "./cmd/observer")
			cmd.Dir = filepath.Join("..", "..")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("go list -deps -tags %s ./cmd/observer: %v\n%s", tags, err, out)
			}
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				if strings.TrimPrefix(strings.TrimSpace(line), modulePath) == sandboxSetupNetLane {
					t.Errorf("-tags %s still links %s", tags, sandboxSetupNetLane)
				}
			}
		})
	}
}
