package sandboxremote

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/docpos"
)

// TestDocCommentsSitOnTheirDeclaration (FX3-A9): every documented
// top-level declaration's comment starts with its own name, so a comment
// never drifts onto the declaration below it (as BuildConsentScreen's and
// neverWorked's had).
func TestDocCommentsSitOnTheirDeclaration(t *testing.T) { docpos.Check(t) }
