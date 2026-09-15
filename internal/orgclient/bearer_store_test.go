package orgclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	keyring "github.com/zalando/go-keyring"
)

func newTestKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv
}

// quietLogger discards WARN output so the fallback-path test stays clean.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestBearerStore_RoundTrip(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T) string // returns fallbackDir
		wantBackend string
	}{
		{
			name: "keychain backend when keyring works",
			setup: func(t *testing.T) string {
				keyring.MockInit()
				return t.TempDir()
			},
			wantBackend: "keychain",
		},
		{
			name: "file fallback when keyring errors",
			setup: func(t *testing.T) string {
				keyring.MockInitWithError(errors.New("no secret service"))
				return t.TempDir()
			},
			wantBackend: "file",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := tc.setup(t)
			st := OpenBearerStore("sbo-test", dir, quietLogger())
			if st.Backend() != tc.wantBackend {
				t.Fatalf("Backend() = %q, want %q", st.Backend(), tc.wantBackend)
			}

			// Nothing stored yet -> ErrNoSecret.
			if _, err := st.LoadBearer(); !errors.Is(err, ErrNoSecret) {
				t.Fatalf("LoadBearer before save: err = %v, want ErrNoSecret", err)
			}
			if _, err := st.LoadAgentKey(); !errors.Is(err, ErrNoSecret) {
				t.Fatalf("LoadAgentKey before save: err = %v, want ErrNoSecret", err)
			}

			// Save + load bearer.
			const bearer = "eyJ.signed.bearer"
			if err := st.SaveBearer(bearer); err != nil {
				t.Fatalf("SaveBearer: %v", err)
			}
			if got, err := st.LoadBearer(); err != nil || got != bearer {
				t.Fatalf("LoadBearer = %q, %v; want %q, nil", got, err, bearer)
			}

			// Save + load agent key.
			key := newTestKey(t)
			if err := st.SaveAgentKey(key); err != nil {
				t.Fatalf("SaveAgentKey: %v", err)
			}
			got, err := st.LoadAgentKey()
			if err != nil {
				t.Fatalf("LoadAgentKey: %v", err)
			}
			if !key.Equal(got) {
				t.Fatalf("LoadAgentKey returned a different key")
			}

			// Save + load the virtual key (third slot, P5a).
			if _, _, err := st.LoadVirtualKey(); !errors.Is(err, ErrNoSecret) {
				t.Fatalf("LoadVirtualKey before save: err = %v, want ErrNoSecret", err)
			}
			const vkey = "sbo-vk-abc123"
			if err := st.SaveVirtualKey(vkey, 7); err != nil {
				t.Fatalf("SaveVirtualKey: %v", err)
			}
			gotKey, gotGen, err := st.LoadVirtualKey()
			if err != nil || gotKey != vkey || gotGen != 7 {
				t.Fatalf("LoadVirtualKey = %q, %d, %v; want %q, 7, nil", gotKey, gotGen, err, vkey)
			}

			// Clear removes all three; loads then report ErrNoSecret.
			if err := st.Clear(); err != nil {
				t.Fatalf("Clear: %v", err)
			}
			if _, err := st.LoadBearer(); !errors.Is(err, ErrNoSecret) {
				t.Fatalf("LoadBearer after Clear: err = %v, want ErrNoSecret", err)
			}
			if _, err := st.LoadAgentKey(); !errors.Is(err, ErrNoSecret) {
				t.Fatalf("LoadAgentKey after Clear: err = %v, want ErrNoSecret", err)
			}
			if _, _, err := st.LoadVirtualKey(); !errors.Is(err, ErrNoSecret) {
				t.Fatalf("LoadVirtualKey after Clear: err = %v, want ErrNoSecret", err)
			}

			// Clear again is a no-op (absence is not an error).
			if err := st.Clear(); err != nil {
				t.Fatalf("Clear (idempotent): %v", err)
			}
		})
	}
}

// The file fallback must write 0600 secrets.
func TestFileStore_Permissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file-mode semantics; Windows does not honor 0o600")
	}
	keyring.MockInitWithError(errors.New("unavailable"))
	dir := t.TempDir()
	st := OpenBearerStore("sbo-perm", dir, quietLogger())
	if st.Backend() != "file" {
		t.Fatalf("Backend() = %q, want file", st.Backend())
	}
	if err := st.SaveBearer("x"); err != nil {
		t.Fatalf("SaveBearer: %v", err)
	}
	p := filepath.Join(dir, "org-bearer", "sbo-perm."+recBearer)
	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat %s: %v", p, err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("bearer file mode = %o, want 600", perm)
	}
}

func TestDecodeAgentKey_Rejects(t *testing.T) {
	if _, err := decodeAgentKey("not-base64!!"); err == nil {
		t.Fatal("expected error for invalid base64")
	}
	if _, err := decodeAgentKey("YWJj"); err == nil { // "abc", wrong size
		t.Fatal("expected error for wrong-size key")
	}
}

func TestVirtualKeyCodec(t *testing.T) {
	enc, err := encodeVirtualKey("sbo-vk-xyz", 42)
	if err != nil {
		t.Fatalf("encodeVirtualKey: %v", err)
	}
	key, gen, err := decodeVirtualKey(enc)
	if err != nil || key != "sbo-vk-xyz" || gen != 42 {
		t.Fatalf("decodeVirtualKey round-trip = %q, %d, %v; want sbo-vk-xyz, 42, nil", key, gen, err)
	}
	if _, _, err := decodeVirtualKey("not-json"); err == nil {
		t.Fatal("expected error decoding non-JSON virtual key record")
	}
}
