package seccorpus

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins seccorpus PURE (CLAUDE.md rule 1): it
// computes over records its caller passes; it opens no file, starts no
// process, makes no network call and imports no other Observer package.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net",
			"net/http",
			"os",
			"os/exec",
			"syscall",
			"math/rand",
			"math/rand/v2",
			"github.com/fsnotify/fsnotify",
		},
		ForbiddenPrefixes: []string{"github.com/marmutapp/superbased-observer/internal/", "golang.org/x/sys"},
		Reason:            "seccorpus is pure: scripts/seccorpus clones, scans and writes files",
	})
}
