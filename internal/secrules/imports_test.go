package secrules

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the rule tables as pure: they read injected
// facts and never reach out.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql", "net/http", "net", "os", "os/exec",
			"github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/store",
			"github.com/marmutapp/superbased-observer/internal/guard",
		},
		Reason: "internal/secrules is pure rule tables over injected facts; the guard core imports nothing from the pillar and the pillar's rules import no guard runtime",
	})
}
