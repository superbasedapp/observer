package passkey_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

const webauthnModule = "github.com/go-webauthn/webauthn"

// TestBoundaryImports pins the verifier as an adapter: no SQL, no HTTP
// server, no store or api import.
func TestBoundaryImports(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net/http",
			"os",
			"os/exec",
			"github.com/jackc/pgx/v5",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/store",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/api",
		},
		Reason: "passkey is the WebAuthn library adapter behind staffauth.Verifier",
	})
}

// TestOnlyThisTreeImportsTheLibrary: go-webauthn is imported by this package
// and its passkeytest helper only, across the cloud service's code, so its
// types cannot spread past the staffauth.Verifier seam (CLAUDE.md Module
// Boundaries #2).
func TestOnlyThisTreeImportsTheLibrary(t *testing.T) {
	t.Parallel()
	here, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	importpin.Check(t, importpin.Spec{
		Dirs:         []string{"../..", "../../../../cmd/observer-cloud"},
		Recursive:    true,
		IncludeTests: true,
		Custom: func(file, importPath string) string {
			if importPath != webauthnModule && !strings.HasPrefix(importPath, webauthnModule+"/") {
				return ""
			}
			abs, err := filepath.Abs(file)
			if err != nil {
				return "cannot resolve " + file
			}
			if abs == here || strings.HasPrefix(abs, here+string(filepath.Separator)) {
				return ""
			}
			return "only internal/cloudserver/staffauth/passkey may import the WebAuthn library"
		},
		Reason: "the WebAuthn library stays behind staffauth.Verifier",
	})
}
