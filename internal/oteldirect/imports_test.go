package oteldirect

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/oteldirect (and its ccfixture
// subpackage) pure (CLAUDE.md "Module Boundaries" rule 1): the HTTP route,
// the token store and the ingest writers live in the org server; this
// package only decides.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Dirs:      []string{"."},
		Recursive: true,
		Forbidden: []string{
			"database/sql",
			"net",
			"net/http",
			"os",
			"os/exec",
			"github.com/fsnotify/fsnotify",
		},
		ForbiddenPrefixes: []string{"github.com/marmutapp/superbased-observer/"},
		Except: []string{
			"github.com/marmutapp/superbased-observer/internal/models",
			"github.com/marmutapp/superbased-observer/internal/orgcontract",
			"github.com/marmutapp/superbased-observer/internal/otlpjson",
			"github.com/marmutapp/superbased-observer/internal/otlpvendor",
			"github.com/marmutapp/superbased-observer/internal/scrub",
			"github.com/marmutapp/superbased-observer/internal/tooltax",
		},
		Reason: "internal/oteldirect must stay pure",
	})
}
