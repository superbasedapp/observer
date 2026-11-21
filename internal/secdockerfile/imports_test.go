package secdockerfile

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the rules as pure over in-memory text.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "net/http", "net", "os", "os/exec", "github.com/fsnotify/fsnotify"},
		Reason:    "internal/secdockerfile is pure rules over Dockerfile text",
	})
}
