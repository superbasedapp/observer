package shiptoken

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/shiptoken pure (CLAUDE.md "Module
// Boundaries" rule 1): the org server's SQL lives in
// internal/orgserver/shiptokenstore, the node's in
// internal/store/cloudsessiontokens.go, and both HTTP seams in their own
// handler files.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net",
			"net/http",
			"os",
			"os/exec",
			"crypto/rand",
			"github.com/fsnotify/fsnotify",
		},
		ForbiddenPrefixes: []string{"github.com/marmutapp/superbased-observer/"},
		Except: []string{
			"github.com/marmutapp/superbased-observer/internal/models",
			"github.com/marmutapp/superbased-observer/internal/orgcontract",
		},
		Reason: "internal/shiptoken must stay pure",
	})
}
