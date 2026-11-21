package paddleapi

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestImports pins the client to net/http and the seat decision: no SQL,
// no file system, no exec.
func TestImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		AllowOnly: true,
		Allowed: []string{
			"bytes", "context", "encoding/json", "errors", "fmt", "io", "net/http", "net/url", "strings",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/seatbilling",
		},
		Reason: "paddleapi sends one kind of request; the decision is seatbilling's",
	})
}
