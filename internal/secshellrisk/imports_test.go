package secshellrisk

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the classifier as pure over in-memory text.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql", "net/http", "net", "os", "os/exec", "github.com/fsnotify/fsnotify",
			// The security.deps component's parser is injected (LangInstalls).
			"github.com/marmutapp/superbased-observer/internal/secfeed",
		},
		Reason: "internal/secshellrisk is pure rules over script text",
	})
}
