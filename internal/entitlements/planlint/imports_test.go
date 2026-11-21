package planlint

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the lint to go/ast and the vocabulary.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		AllowOnly: true,
		Allowed: []string{
			"go/ast", "go/token", "sort", "strconv", "strings",
			"github.com/marmutapp/superbased-observer/internal/entitlements",
		},
		Reason: "planlint reads a parsed file and the plan vocabulary, nothing else",
	})
}
