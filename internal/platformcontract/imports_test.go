package platformcontract

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the package to a closed stdlib allow-list: no
// database/sql, net/http or fsnotify.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		AllowOnly: true,
		Allowed: []string{
			"crypto/ed25519", "crypto/sha256", "encoding/base64", "encoding/hex",
			"errors", "fmt", "strconv", "strings", "time",
		},
		Reason: "platformcontract closed allow-list",
	})
}
