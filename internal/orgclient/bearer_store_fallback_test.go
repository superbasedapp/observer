package orgclient

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	keyring "github.com/zalando/go-keyring"
)

// TestKeychainStoreReadsFileFallback (issue 1b, WINNODE merge follow-up): a
// node enrolled where the OS keychain was unavailable (Windows over SSH or
// WMI, no logon session) holds its bearer and agent key in the 0600 file
// store. A daemon started later from the developer's sign-in has a working
// keychain that holds no bearer; it must read the file store, or it treats
// the node as not enrolled and never pushes. When both hold one the
// keychain wins, and unenrol clears both.
func TestKeychainStoreReadsFileFallback(t *testing.T) {
	fileKey, chainKey := newTestKey(t), newTestKey(t)
	cases := []struct {
		name        string
		file, chain bool
		wantBearer  string
		wantKey     ed25519.PrivateKey
	}{
		{"file only (enrolled with no keychain)", true, false, "file-bearer", fileKey},
		{"keychain only", false, true, "chain-bearer", chainKey},
		{"both present: keychain wins", true, true, "chain-bearer", chainKey},
		{"neither: not enrolled", false, false, "", nil},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keyring.MockInit()
			dir := t.TempDir()
			service := fmt.Sprintf("sbo-fallback-%d", i)
			if tc.file {
				// What OpenBearerStore returns when the keychain is unavailable.
				keyring.MockInitWithError(errors.New("no logon session"))
				fs := OpenBearerStore(service, dir, quietLogger())
				if fs.Backend() != "file" {
					t.Fatalf("precondition: Backend() = %q, want file", fs.Backend())
				}
				if err := fs.SaveBearer("file-bearer"); err != nil {
					t.Fatal(err)
				}
				if err := fs.SaveAgentKey(fileKey); err != nil {
					t.Fatal(err)
				}
				keyring.MockInit()
			}
			st := OpenBearerStore(service, dir, quietLogger())
			if st.Backend() != "keychain" {
				t.Fatalf("Backend() = %q, want keychain", st.Backend())
			}
			if tc.chain {
				if err := st.SaveBearer("chain-bearer"); err != nil {
					t.Fatal(err)
				}
				if err := st.SaveAgentKey(chainKey); err != nil {
					t.Fatal(err)
				}
			}
			bearer, err := st.LoadBearer()
			key, kerr := st.LoadAgentKey()
			if tc.wantBearer == "" {
				if !errors.Is(err, ErrNoSecret) || !errors.Is(kerr, ErrNoSecret) {
					t.Fatalf("LoadBearer err = %v, LoadAgentKey err = %v; want ErrNoSecret for both", err, kerr)
				}
			} else {
				if err != nil || bearer != tc.wantBearer {
					t.Fatalf("LoadBearer = %q, %v; want %q", bearer, err, tc.wantBearer)
				}
				if kerr != nil || !key.Equal(tc.wantKey) {
					t.Fatalf("LoadAgentKey = %v; want the %s key", kerr, map[bool]string{true: "keychain", false: "file"}[tc.chain])
				}
			}
			if tc.file {
				if _, err := os.Stat(filepath.Join(dir, "org-bearer", service+"."+recBearer)); err != nil {
					t.Fatalf("a load must leave the file store in place: %v", err)
				}
			}
			// Unenrol clears both stores, so a cleared node never falls back
			// to a stale file bearer.
			if err := st.Clear(); err != nil {
				t.Fatalf("Clear: %v", err)
			}
			if _, err := st.LoadBearer(); !errors.Is(err, ErrNoSecret) {
				t.Fatalf("LoadBearer after Clear: err = %v, want ErrNoSecret", err)
			}
			if _, err := st.LoadAgentKey(); !errors.Is(err, ErrNoSecret) {
				t.Fatalf("LoadAgentKey after Clear: err = %v, want ErrNoSecret", err)
			}
		})
	}
}
