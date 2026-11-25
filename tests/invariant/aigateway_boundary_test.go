package invariant

import (
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
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
	// A _test.go file is removed with the feature it drives and does not
	// couple the shipped binary, so it is exempt (same rationale as the
	// obs boundary test): importpin skips test files unless asked.
	importpin.Check(t, importpin.Spec{
		Dirs:           []string{filepath.Join("..", "..", "internal", "proxy")},
		Recursive:      true,
		ForbiddenTrees: aigatewayForbiddenByProxy,
		Reason:         "internal/proxy must never import the AI Gateway or org server (design §2.2 reverse-import rule)",
	})
}
