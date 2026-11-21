package seatbilling

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the decision pure; the HTTP client is the
// paddleapi subpackage.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		AllowOnly: true,
		Allowed:   []string{"context", "encoding/json", "fmt", "time"},
		Reason:    "seatbilling decides; paddleapi sends",
	})
}
