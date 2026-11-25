package docpos

import "testing"

// TestDocCommentsSitOnTheirDeclaration runs the check on this package's own
// source.
func TestDocCommentsSitOnTheirDeclaration(t *testing.T) { Check(t) }
