package keystoretest

import (
	"testing"

	keyring "github.com/zalando/go-keyring"

	"github.com/marmutapp/superbased-observer/internal/keystore"
)

// UseTestKeyring gives the calling test a fresh, empty in-memory keyring and
// gives the next test another fresh one when it ends. The in-memory keyring a
// test binary runs on is ONE map for the whole process, so a test that opens
// a store on its own t.TempDir() and expects it empty (no API token, no
// refresh material) otherwise sees what an earlier test stored under the same
// service: the fallback directory scopes the file backend only, never the
// keychain. It fails the test if this process reaches the OS keychain, so it
// can never clear a real store. Tests that call it must not run in parallel
// with other keyring users.
func UseTestKeyring(tb testing.TB) {
	tb.Helper()
	if keystore.OSKeyringActive() {
		tb.Fatal("keystoretest.UseTestKeyring: this process reaches the OS keychain; refusing to reset it")
	}
	keyring.MockInit()
	tb.Cleanup(keyring.MockInit)
}
