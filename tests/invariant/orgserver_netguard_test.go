package invariant

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOrgServerOutboundIsGuarded pins MS-R-001 at the source level: no org
// server package falls back to http.DefaultClient (no timeout, no destination
// check, redirects followed) or the package-level http.Get/Post/Head helpers
// that use it, and every package that calls a customer- or admin-supplied URL
// builds its client through internal/netguard, whose clients always carry a
// non-zero timeout (netguard.TestDefaultClient).
func TestOrgServerOutboundIsGuarded(t *testing.T) {
	skipInPublicTree(t, repoRoot(t), "internal/orgserver")
	root := repoRoot(t)
	forbidden := []string{"http.DefaultClient", "http.Get(", "http.Post(", "http.Head(", "http.PostForm("}
	err := filepath.WalkDir(filepath.Join(root, "internal", "orgserver"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		for i, line := range strings.Split(string(raw), "\n") {
			code := line
			if c := strings.Index(code, "//"); c >= 0 {
				code = code[:c]
			}
			for _, f := range forbidden {
				if strings.Contains(code, f) {
					rel, _ := filepath.Rel(root, p)
					t.Errorf("%s:%d uses %s; build the client with internal/netguard (MS-R-001)", filepath.ToSlash(rel), i+1, f)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The customer-URL egress sites, each of which must build its default
	// client through netguard.
	sites := []string{
		"internal/orgserver/obsalert/obsalert.go",
		"internal/orgserver/budget/budget.go",
		"internal/orgserver/auth/oidc.go",
		"internal/orgserver/auth/saml.go",
		"internal/orgserver/authsettings_handlers.go",
		"internal/orgserver/llmprovider/client.go",
		"internal/orgserver/ccanalytics/poller.go",
		"internal/orgserver/codexanalytics/poller.go",
		"internal/orgserver/copilotanalytics/poller.go",
		"internal/orgserver/cortexanalytics/sqlapi.go",
		"internal/orgserver/kimchianalytics/poller.go",
		"internal/orgserver/m365copilotanalytics/auth.go",
		"internal/orgserver/m365copilotanalytics/poller.go",
	}
	for _, s := range sites {
		t.Run(s, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(s)))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), "netguard.") {
				t.Errorf("%s does not build its outbound client through internal/netguard", s)
			}
		})
	}
}
