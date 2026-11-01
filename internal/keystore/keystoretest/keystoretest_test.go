package keystoretest

import (
	"errors"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/keystore"
)

// TestUseTestKeyringStartsEmpty: the in-memory keyring is one map per test
// binary, so a value an earlier test stored is seen by a later test's store
// unless that test asks for a fresh keyring (the cloudclient failures on the
// release line: a test expecting no API token read an earlier test's).
func TestUseTestKeyringStartsEmpty(t *testing.T) {
	if err := keystore.KeyringSet("svc-fresh", "rec", "left-by-an-earlier-test"); err != nil {
		t.Fatal(err)
	}
	if v, err := keystore.KeyringGet("svc-fresh", "rec"); err != nil || v == "" {
		t.Fatalf("the shared keyring does not hold the earlier value: %q %v", v, err)
	}
	t.Run("fresh", func(t *testing.T) {
		UseTestKeyring(t)
		if v, err := keystore.KeyringGet("svc-fresh", "rec"); !errors.Is(err, keystore.ErrKeyringNotFound) {
			t.Fatalf("a fresh keyring still holds %q (%v)", v, err)
		}
	})
}
