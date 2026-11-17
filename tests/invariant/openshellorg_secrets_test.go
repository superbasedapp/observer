package invariant

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// openshellorg_secrets_test.go fences the org-hosted OpenShell row's secrets
// (tracker F-019, g1-design.md sections 5.5 and 9.1, lane G4): the sign-in
// grant handle's keystore service name and the agent token routes appear in
// production Go only in their owning files, never in the org push wire
// builder (internal/store/orgpush.go), the support bundle builder or a log
// line's format string. The handle and every run token live in the daemon's
// memory and the keystore only.

// openShellOrgSecretNeedles are the strings fenced.
var openShellOrgSecretNeedles = []string{"sbo-openshell-org-grant-v1", "/api/agent/sandbox/openshell"}

// openShellOrgSecretOwners are the production files (slash paths; a trailing
// "/" is a directory, "*" a file-name prefix) that may name a needle.
var openShellOrgSecretOwners = []string{
	// The row's keystore field (uninstall reads it) and the vendor row.
	"internal/sandboxbackend/registry.go",
	"internal/sandboxremote/vendors.go",
	// The component rows' surface text.
	"internal/components/catalog_node.go",
	"internal/components/catalog_server.go",
	// The node's agent-route client and the node verbs that hold the handle.
	"internal/orgclient/openshellorg.go",
	"cmd/observer/sandbox_orgshell_login*",
	"cmd/observer/sandbox_orgshell_hold*",
	// The server side of the routes (lanes G2 and G3).
	"internal/orgserver/openshellctl/",
	"internal/orgserver/openshellgw/",
	"internal/orgserver/server_openshell*",
	// The pooled route inventory (plan 07 wave 10 L2): one row per mounted
	// route, so it spells the agent token routes exactly as mounted
	// (TestEveryRouteHasAPooledRow matches them); it holds no grant or token
	// and logs nothing.
	"internal/orgserver/pooledroutes/routes.go",
}

// openShellOrgSecretForbidden are files that must never name a needle, even
// if a later allow-list entry would cover them.
var openShellOrgSecretForbidden = []string{
	"internal/store/orgpush.go",
	"cmd/observer-org/supportbundle.go",
	"cmd/observer-org/supportbundle_agentaccess.go",
}

func TestOpenShellOrgSecretsFenced(t *testing.T) {
	root := repoRoot(t)
	owned := 0
	for _, rel := range goSourceFiles(t, root) {
		if strings.HasSuffix(rel, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		src := string(b)
		for _, n := range openShellOrgSecretNeedles {
			if !strings.Contains(src, n) {
				continue
			}
			if allowedBy(rel, openShellOrgSecretForbidden) {
				t.Errorf("%s names %q: the push wire, the support bundle and logs never carry the grant or the token routes", rel, n)
				continue
			}
			if !allowedBy(rel, openShellOrgSecretOwners) {
				t.Errorf("%s names %q outside its owning files", rel, n)
				continue
			}
			owned++
			for _, line := range strings.Split(src, "\n") {
				if strings.Contains(line, n) && logFormatLine(line) {
					t.Errorf("%s: a log line names %q: %s", rel, n, strings.TrimSpace(line))
				}
			}
		}
	}
	if owned == 0 {
		t.Fatal("no owning file names a needle: the fence would be vacuous")
	}
}

// logFormatLine reports whether a source line is a log call.
func logFormatLine(line string) bool {
	for _, call := range []string{"slog.", "log.Print", "Logger.", ".Info(", ".Warn(", ".Error(", ".Debug("} {
		if strings.Contains(line, call) {
			return true
		}
	}
	return false
}
