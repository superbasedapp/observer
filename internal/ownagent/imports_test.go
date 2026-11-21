package ownagent

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/ownagent pure (CLAUDE.md "Module
// Boundaries" rule 1): the proxy reads the headers, the store writes the
// session row, and this package only turns strings into a claim.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net/http",
			"github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/store",
		},
		Reason: "internal/ownagent must stay pure",
	})
}
