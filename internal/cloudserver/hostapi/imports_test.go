package hostapi

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestBoundaryImports pins hostapi as the pure core of the host-API client
// (design m6.0 section 6: "hostapi pure cores import no database/sql,
// net/http"): the wire contract and a closed standard-library list, no
// transport, no SQL, no store, no keys on disk.
func TestBoundaryImports(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		AllowOnly: true,
		Allowed: []string{
			"bytes", "encoding/json", "errors", "fmt", "slices", "strconv", "strings", "time",
			// The usage report's body digest (usage.go): pure hashing, no I/O.
			"crypto/sha256", "encoding/hex",
			"github.com/marmutapp/superbased-observer/internal/platformcontract",
		},
		Reason: "hostapi is the pure host-API client core; I/O lives in hostapi/hostclient",
	})
}
