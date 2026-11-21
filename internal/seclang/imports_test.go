package seclang

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/seclang pure (CLAUDE.md "Module
// Boundaries" rule 1): a data table and its lookups, no database, no
// connection and no file read of its own; the SQL that reads the table
// lives in the store.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net/http",
			"os",
			"os/exec",
			"io/ioutil",
			"github.com/fsnotify/fsnotify",
		},
		Reason: "internal/seclang must stay pure: a table and its lookups, nothing else",
	})
}
