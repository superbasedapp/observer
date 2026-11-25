package securityscanning

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		ForbiddenTrees: []string{
			"database/sql",
			"net/http",
			"os/exec",
			"github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/config",
			"github.com/marmutapp/superbased-observer/internal/store",
			"github.com/marmutapp/superbased-observer/internal/orgserver",
			"github.com/marmutapp/superbased-observer/internal/componentstate",
		},
		Reason: "internal/policyfam/securityscanning must stay pure; the cmd layer supplies NodeFacts",
	})
}
