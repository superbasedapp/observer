package remotecfg

import (
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/fsatomic"
)

// TestRemoteSecretIsOwnerOnly (R-160): the pairing secret's hash is written
// owner-only: 0600 on POSIX, and on Windows a protected DACL granting this
// user and SYSTEM only.
func TestRemoteSecretIsOwnerOnly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "remote-secret")
	if err := writeRemoteSecretAtomic(p, "$argon2id$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA"); err != nil {
		t.Fatal(err)
	}
	ok, err := fsatomic.IsOwnerOnly(p)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("the remote secret file is not owner-only")
	}
}
