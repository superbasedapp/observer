package guardrecipe

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins internal/guardrecipe PURE (CLAUDE.md module
// rule 1): no I/O packages and no Observer package. The rule catalog arrives
// as data and the compiled file is linted by the guard at the I/O boundary
// (internal/guardrecipesvc), so the policy grammar keeps one owner.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"os", "os/exec", "path/filepath", "net/http", "database/sql",
			"github.com/fsnotify/fsnotify",
		},
		ForbiddenPrefixes: []string{"github.com/marmutapp/superbased-observer/"},
		Reason:            "guard recipes are pure: catalog in as data, I/O at internal/guardrecipesvc",
	})
}
