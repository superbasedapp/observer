package filehash

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the module boundary (CLAUDE.md section 1):
// this package hashes a file and nothing else.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		AllowOnly: true,
		Allowed:   []string{"crypto/sha256", "encoding/hex", "io", "os"},
		Reason:    "internal/filehash only reads and hashes a file",
	})
}
