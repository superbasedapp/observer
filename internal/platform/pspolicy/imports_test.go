package pspolicy

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins pspolicy PURE (CLAUDE.md Module
// Boundaries #1): the policy answer is read by the caller and passed in.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		AllowOnly: true,
		Allowed:   []string{"errors", "strings"},
		Reason:    "pspolicy must stay pure: the execution-policy answer is injected",
	})
}
