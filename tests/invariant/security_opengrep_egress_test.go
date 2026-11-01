package invariant

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// security_opengrep_egress_test.go is the dedicated pin of the
// security.scan.opengrep.net lane (egress_lanes_test.go; security plan
// sections 8.1 and 8.5, ledger SECP-29): the code rules' network client,
// internal/secscan/opengrep/opengrepnet (the guided install's release
// download and the signed feed), is linked only into the cmd layer, never
// into the always-on daemon paths, the hook, the driver or the pure
// engine and pack packages.

var securityOpengrepLane = "internal/secscan/opengrep/opengrepnet"

var securityOpengrepForbiddenEntries = []string{
	"internal/watcher",
	"internal/proxy",
	"internal/store",
	"internal/hook",
	"internal/hookctx",
	"internal/secsvc",
	"internal/secscan",
	"internal/secscan/opengrep",
	"internal/secengine",
	"internal/secrulepack",
	"internal/contentchan",
	"internal/orgclient",
}

func TestEgressSecurityOpengrepNotLinkedByDaemonPaths(t *testing.T) {
	toolchainTest(t)
	root := filepath.Join("..", "..")
	for _, entry := range securityOpengrepForbiddenEntries {
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
				if rel == securityOpengrepLane {
					t.Errorf("%s transitively imports %s: the code rules' network lane is linked only into the cmd layer", entry, securityOpengrepLane)
				}
			}
			if !self {
				t.Fatalf("go list -deps ./%s did not list the package itself; the guard would be vacuous", entry)
			}
		})
	}
}

// TestEgressSecurityOpengrepImporters: only cmd/observer imports the lane.
func TestEgressSecurityOpengrepImporters(t *testing.T) {
	toolchainTest(t)
	pkgs := moduleImports(t, "")
	for pkg, imports := range pkgs {
		for _, imp := range imports {
			if imp == modulePath+securityOpengrepLane && pkg != "cmd/observer" {
				t.Errorf("%s imports %s; only cmd/observer may", pkg, securityOpengrepLane)
			}
		}
	}
}

// TestSecurityOpengrepNeverOnTheHookPath: the code rules' driver runs only
// from the daemon loop and the CLI (lane SEC-G2): never in a hook and never
// in the commit gate's quick scan, so neither path links it. The hook
// command itself lives in cmd/observer, which links the driver for the
// daemon, so its import graph proves nothing:
// TestSecurityOpengrepNotReachedFromTheHookCommand walks that package's
// declarations from newHookCmd instead (audit finding 7).
func TestSecurityOpengrepNeverOnTheHookPath(t *testing.T) {
	toolchainTest(t)
	root := filepath.Join("..", "..")
	for _, entry := range []string{"internal/hook", "internal/hookctx", "internal/secquickscan", "internal/secipc", "internal/secpostwrite"} {
		cmd := exec.Command("go", "list", "-deps", "./"+entry)
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("go list -deps ./%s: %v\n%s", entry, err, out)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if strings.HasPrefix(strings.TrimPrefix(strings.TrimSpace(line), modulePath), "internal/secscan/opengrep") {
				t.Errorf("%s links %s: the code rules never run on the hook path or in the quick scan", entry, strings.TrimSpace(line))
			}
		}
	}
}
