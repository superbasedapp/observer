package secdast

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/secdast pure (CLAUDE.md "Module
// Boundaries" rule 1; plan section 14.13 "Test strategy"): it decides, the
// security.dast lane (internal/secdastnet) dials. No network, file,
// database, process or fsnotify import, and no store.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net",
			"net/http",
			"net/http/httptest",
			"crypto/tls",
			"os",
			"os/exec",
			"io/ioutil",
			"syscall",
			"github.com/fsnotify/fsnotify",
		},
		ForbiddenTrees: []string{
			"github.com/marmutapp/superbased-observer/internal/store",
			"github.com/marmutapp/superbased-observer/internal/secdastnet",
		},
		Reason: "internal/secdast must stay pure: internal/secdastnet is the only package that dials",
	})
}
