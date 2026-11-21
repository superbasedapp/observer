package netpolicy

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/netpolicy as a pure primitive (CLAUDE.md module rule 1): no I/O
// imports and no Observer package at all.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden:         []string{"database/sql", "net/http", "github.com/fsnotify/fsnotify"},
		ForbiddenPrefixes: []string{"github.com/marmutapp/superbased-observer/"},
		// The one allowed Observer import is the stdlib-only IP classifier,
		// so classification has exactly one owner (internal/ipclass).
		Except: []string{"github.com/marmutapp/superbased-observer/internal/ipclass"},
		Reason: "netpolicy must not depend on any Observer package except the pure ipclass leaf",
	})
}
