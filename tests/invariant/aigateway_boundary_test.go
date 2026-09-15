package invariant

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// aigatewayForbiddenByProxy are the import prefixes internal/proxy must never
// reach for. The AI Gateway (internal/aigateway) and the org server
// (internal/orgserver) are SERVER-SIDE planes; the node proxy is a separate
// binary that must not depend on either (design §2.2 reverse-import rule,
// mirror of the internal/obs boundary). A leaked import here would couple the
// node's data plane to org-server code, breaking the two-binary separation
// and the v1.5 standalone-gateway extraction.
var aigatewayForbiddenByProxy = []string{
	"github.com/marmutapp/superbased-observer/internal/aigateway",
	"github.com/marmutapp/superbased-observer/internal/orgserver",
}

// TestProxyDoesNotImportGatewayOrOrgServer enforces the design §2.2
// reverse-import rule: internal/proxy never imports internal/aigateway or
// internal/orgserver. It textually scans production imports (build-tag
// agnostic, _test.go exempt like the obs boundary) so a leaked import fails
// here before the offending commit can land.
func TestProxyDoesNotImportGatewayOrOrgServer(t *testing.T) {
	root := filepath.Join("..", "..", "internal", "proxy")
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		// A _test.go file is removed with the feature it drives and does not
		// couple the shipped binary, so it is exempt (same rationale as the
		// obs boundary test).
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		af, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}
		slashed := filepath.ToSlash(path)
		for _, imp := range af.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range aigatewayForbiddenByProxy {
				if p == bad || strings.HasPrefix(p, bad+"/") {
					t.Errorf("%s imports %q — internal/proxy must never import the AI Gateway or org server (design §2.2 reverse-import rule)", slashed, p)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
}
