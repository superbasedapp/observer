package invariant

import (
	"sort"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestRouteWritersIntoCredentialFilesAreDeclared pins the route half of the
// D-268 / D-270 credential-file rule (surface-gap FU-33, D9), the twin of
// TestHookWritersIntoCredentialFilesAreDeclared:
//
//   - every route span the agentconfig catalogue computes in a file it
//     marks Secret (or never readable) belongs to a row whose route
//     declares integration.ProxyRoute.SharesCredentialFile;
//   - every registry row whose route writes a vendor file (a persisted
//     route kind, or a launcher that writes its own provider entry) either
//     declares the exception or is listed below with the reason its file
//     holds no credential;
//   - every declared route names its reason.
func TestRouteWritersIntoCredentialFilesAreDeclared(t *testing.T) {
	secretShapes := map[string]bool{}
	for _, row := range agentconfig.Catalog() {
		if row.Secret {
			secretShapes[row.Tool+"\x00"+row.FileID] = true
		}
	}
	never := map[string]bool{}
	for _, f := range agentconfig.Files() {
		if f.WriteNeeds == agentconfig.PrivNever {
			never[f.ID] = true
		}
	}
	var missing []string
	for _, s := range agentconfig.OwnedSpans() {
		if s.Owner != agentconfig.SpanOwnerProxyRoute {
			continue
		}
		if !secretShapes[s.Tool+"\x00"+s.Shape] && !never[s.FileID] {
			continue
		}
		if !integration.RouteSharesCredentialFile(s.Tool) {
			missing = append(missing, s.Tool+" ("+s.FileID+", "+s.Writer+")")
		}
	}
	// Rows whose route writes a file that holds no credential (none today).
	noCredential := map[string]string{}
	for _, c := range integration.Capabilities() {
		for _, r := range []*integration.ProxyRoute{c.Proxy, c.ProxyProbe} {
			if r == nil {
				continue
			}
			if r.SharesCredentialFile && r.CredentialFileReason == "" {
				t.Errorf("%s: route declares the credential-file exception without a reason", c.Tool)
			}
			if !r.SharesCredentialFile && r.CredentialFileReason != "" {
				t.Errorf("%s: route carries a credential-file reason without the flag", c.Tool)
			}
			if !routeWritesVendorFile(r) || r.SharesCredentialFile {
				continue
			}
			if _, ok := noCredential[c.Tool]; !ok {
				missing = append(missing, c.Tool+" ("+string(r.Kind)+" route writes a vendor file)")
			}
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("route writers into credential-bearing files without ProxyRoute.SharesCredentialFile: %v", missing)
	}
	if len(integration.CredentialFileRouteTools()) == 0 {
		t.Fatal("no route declares the exception: the cross-check is not looking at anything")
	}
	t.Logf("route writers under the credential-file exception: %v", integration.CredentialFileRouteTools())
}

// routeWritesVendorFile reports a route whose writer edits a vendor config
// file: a persisted kind, or a launcher route that writes its own provider
// entry before exec (Kind launcher with no env var: prime-agent).
func routeWritesVendorFile(r *integration.ProxyRoute) bool {
	switch r.Kind {
	case integration.RouteEnvSettings, integration.RouteConfigFile, integration.RouteProviderJSON, integration.RouteVSCodeSettings:
		return true
	case integration.RouteLauncher:
		return r.EnvVar == ""
	}
	return false
}
