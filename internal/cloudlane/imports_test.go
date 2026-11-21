package cloudlane

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/cloudlane pure (CLAUDE.md section 1).
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net/http",
			"os/exec",
			"github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/store",
		},
		ForbiddenPrefixes: []string{
			"github.com/marmutapp/superbased-observer/internal/adapter/",
			"modernc.org/sqlite",
		},
		Reason: "internal/cloudlane must stay pure",
	})
}
