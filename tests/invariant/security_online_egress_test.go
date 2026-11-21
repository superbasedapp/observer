package invariant

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// security_online_egress_test.go is the dedicated pin of the security.online
// lane (egress_lanes_test.go; security pillar plan section 8.3, SECP-7): the
// install gate's public online client, internal/secfeed/online, sends
// package names the user did not type, so the always-on daemon paths, the
// hook, the pure install-gate core and the ask channel must never link it.
// It is reached only from the daemon's security service in cmd/observer,
// which hands it to the service on an individual node and never on a
// managed one (the zero-request test in cmd/observer).

// securityOnlinePackage is the lane's package.
const securityOnlinePackage = "internal/secfeed/online"

// securityOnlineForbiddenEntries may not reach it transitively.
var securityOnlineForbiddenEntries = []string{
	"internal/watcher",
	"internal/proxy",
	"internal/store",
	"internal/hook",
	"internal/hookctx",
	"internal/secfeed",
	"internal/secask",
	"internal/secrules",
	"internal/secverify",
	"internal/orgclient",
}

func TestEgressSecurityOnlineNotLinkedByDaemonPaths(t *testing.T) {
	toolchainTest(t)
	root := filepath.Join("..", "..")
	for _, entry := range securityOnlineForbiddenEntries {
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
				if rel == securityOnlinePackage {
					t.Errorf("%s transitively imports %s: the public online client is linked only into the daemon's security service", entry, securityOnlinePackage)
				}
			}
			if !self {
				t.Fatalf("go list -deps ./%s did not list the package itself; the guard would be vacuous", entry)
			}
		})
	}
}

// securityOnlineImporters are the only module packages that may import the
// client directly: cmd/observer (its security deps wiring) and, in the org
// server binary, the org.security.relay wiring (internal/orgserver's
// secrelay_wire.go, the relay mode's upstream, and secrelay_sync_wire.go,
// the opt-in scheduled mirror sync) and cmd/observer-org
// (`observer-org security mirror sync`), declared as the server egress lane
// org.security.relay (server_egress_lanes_test.go; lane SEC-E4).
var securityOnlineImporters = map[string]bool{
	"cmd/observer": true, "internal/orgserver": true, "cmd/observer-org": true,
}

// TestEgressSecurityOnlineImporters: the only module packages importing the
// client directly are securityOnlineImporters.
func TestEgressSecurityOnlineImporters(t *testing.T) {
	toolchainTest(t)
	cmd := exec.Command("go", "list", "-f", "{{.ImportPath}} {{join .Imports \" \"}}", "./...")
	cmd.Dir = filepath.Join("..", "..")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list ./...: %v\n%s", err, out)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		rel := strings.TrimPrefix(f[0], modulePath)
		for _, imp := range f[1:] {
			if strings.TrimPrefix(imp, modulePath) == securityOnlinePackage && !securityOnlineImporters[rel] {
				t.Errorf("%s imports %s; only cmd/observer's security deps wiring and the org relay's wiring may", rel, securityOnlinePackage)
			}
		}
	}
}
