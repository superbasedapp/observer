package passkeytest

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestBoundaryImports pins the software authenticator as pure test support:
// standard library crypto and encoding plus the WebAuthn library's CBOR
// encoder, nothing that does I/O.
func TestBoundaryImports(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		StdlibOnly:   true,
		AllowedTrees: []string{"github.com/go-webauthn/webauthn/protocol/webauthncbor"},
		Forbidden:    []string{"net", "net/http", "os", "os/exec", "database/sql"},
		Reason:       "passkeytest builds WebAuthn responses in memory; it does no I/O",
	})
}
