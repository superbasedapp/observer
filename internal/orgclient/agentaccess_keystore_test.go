package orgclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	keyring "github.com/zalando/go-keyring"

	"github.com/marmutapp/superbased-observer/internal/dpop/jose"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Every test here runs against go-keyring's in-process mock (MockInit /
// MockInitWithError) and a t.TempDir() fallback directory - never the real OS
// keychain and never the real ~/.observer.

const aakTestService = "sbo-aak-file-test"

func skipIfNoFileFallback(t *testing.T) {
	t.Helper()
	if !agentAccessKeyFileSupported || runtime.GOOS == "windows" {
		t.Skip("the agent-access key file fallback is unix-only")
	}
}

func newAAKey(t *testing.T) AgentAccessKey {
	t.Helper()
	signer, err := jose.GenerateKey(rand.Reader, DefaultAgentAccessKeyAlg)
	if err != nil {
		t.Fatal(err)
	}
	return AgentAccessKey{Alg: DefaultAgentAccessKeyAlg, Signer: signer}
}

func sameAAKey(t *testing.T, a, b AgentAccessKey) bool {
	t.Helper()
	ja, err := jose.PublicJWK(a.Signer.Public(), a.Alg, "")
	if err != nil {
		t.Fatal(err)
	}
	jb, err := jose.PublicJWK(b.Signer.Public(), b.Alg, "")
	if err != nil {
		t.Fatal(err)
	}
	return ja == jb
}

func aakFilePath(dir string) string {
	return filepath.Join(dir, "org-bearer", aakTestService+"."+recAgentAccessKey)
}

// seedAAKeyFile writes a key into the file fallback (by opening with the
// keychain down) and returns it.
func seedAAKeyFile(t *testing.T, dir string) AgentAccessKey {
	t.Helper()
	keyring.MockInitWithError(errors.New("no secret service"))
	st, err := OpenAgentAccessKeyStoreIn(aakTestService, dir, quietLogger())
	if err != nil {
		t.Fatalf("open (file): %v", err)
	}
	k := newAAKey(t)
	if err := st.SaveAgentAccessKey(k); err != nil {
		t.Fatalf("save (file): %v", err)
	}
	return k
}

func seedAAKeyKeychain(t *testing.T) AgentAccessKey {
	t.Helper()
	k := newAAKey(t)
	v, err := encodeAgentAccessKey(k)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.Set(aakTestService, recAgentAccessKey, v); err != nil {
		t.Fatal(err)
	}
	return k
}

// TestAgentAccessKeyStoreBackendSelection walks the selection table in
// agentaccess_keystore.go, one case per row.
func TestAgentAccessKeyStoreBackendSelection(t *testing.T) {
	skipIfNoFileFallback(t)
	tests := []struct {
		name string
		// setup prepares the keychain mock + dir and returns the key the
		// store must load (nil: none stored yet).
		setup    func(t *testing.T, dir string) *AgentAccessKey
		wantFile bool
	}{
		{
			name: "row 1: keychain usable and holds the key -> keychain (even with a stale file)",
			setup: func(t *testing.T, dir string) *AgentAccessKey {
				_ = seedAAKeyFile(t, dir)
				keyring.MockInit()
				k := seedAAKeyKeychain(t)
				return &k
			},
			wantFile: false,
		},
		{
			name: "row 2: keychain usable, only the file holds the key -> file (no silent rotation)",
			setup: func(t *testing.T, dir string) *AgentAccessKey {
				k := seedAAKeyFile(t, dir)
				keyring.MockInit()
				return &k
			},
			wantFile: true,
		},
		{
			name: "row 3: keychain usable, no key anywhere -> keychain",
			setup: func(t *testing.T, dir string) *AgentAccessKey {
				keyring.MockInit()
				return nil
			},
			wantFile: false,
		},
		{
			name: "row 4: keychain unusable -> hardened file",
			setup: func(t *testing.T, dir string) *AgentAccessKey {
				keyring.MockInitWithError(errors.New("no secret service"))
				return nil
			},
			wantFile: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer keyring.MockInit()
			dir := t.TempDir()
			want := tc.setup(t, dir)
			st, err := OpenAgentAccessKeyStoreIn(aakTestService, dir, quietLogger())
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			wantLoc := "keychain"
			if tc.wantFile {
				wantLoc = "file " + aakFilePath(dir)
			}
			if got := AgentAccessKeyLocation(st); got != wantLoc {
				t.Fatalf("location = %q, want %q", got, wantLoc)
			}
			got, err := st.LoadAgentAccessKey()
			if want == nil {
				if !errors.Is(err, ErrNoSecret) {
					t.Fatalf("load of an empty store = %v, want ErrNoSecret", err)
				}
				k, created, ensureErr := EnsureAgentAccessKey(st)
				if ensureErr != nil || !created {
					t.Fatalf("ensure = %v created=%v", ensureErr, created)
				}
				want = &k
				got, err = st.LoadAgentAccessKey()
			}
			if err != nil || !sameAAKey(t, got, *want) {
				t.Fatalf("load = %v (same=%v)", err, err == nil && sameAAKey(t, got, *want))
			}
			// The write landed in the selected backend only.
			_, kcErr := keyring.Get(aakTestService, recAgentAccessKey)
			_, fErr := os.Lstat(aakFilePath(dir))
			if tc.wantFile && fErr != nil {
				t.Fatalf("file backend but no file: %v", fErr)
			}
			if !tc.wantFile && kcErr != nil {
				t.Fatalf("keychain backend but no keychain record: %v", kcErr)
			}
		})
	}
}

// TestAgentAccessKeyFileFallbackPermsAndRoundTrip: with the keychain down the
// key lands in a 0600 file inside a 0700 dir, with the keychain envelope, and
// a fresh open loads the same key.
func TestAgentAccessKeyFileFallbackPermsAndRoundTrip(t *testing.T) {
	skipIfNoFileFallback(t)
	defer keyring.MockInit()
	dir := t.TempDir()
	want := seedAAKeyFile(t, dir)
	p := aakFilePath(dir)
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key file mode = %o, want 600", perm)
	}
	di, err := os.Stat(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Fatalf("key dir mode = %o, want 700", perm)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw), agentAccessKeyEnvelope+":"+DefaultAgentAccessKeyAlg+":") {
		t.Fatalf("file does not hold the keychain envelope: %.20q", raw)
	}
	// No temp file is left behind by the atomic write.
	entries, _ := os.ReadDir(filepath.Dir(p))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Fatalf("leftover temp file %s", e.Name())
		}
	}
	st, err := OpenAgentAccessKeyStoreIn(aakTestService, dir, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.LoadAgentAccessKey()
	if err != nil || !sameAAKey(t, got, want) {
		t.Fatalf("reload = %v", err)
	}
}

// TestAgentAccessKeyFileRefusals: a group/world-readable key file, a
// symlinked key file, and a lax key directory are all refused.
func TestAgentAccessKeyFileRefusals(t *testing.T) {
	skipIfNoFileFallback(t)
	tests := []struct {
		name   string
		mangle func(t *testing.T, dir string)
		// openFails: the refusal happens at open (directory), not at load.
		openFails bool
	}{
		{name: "0644 file", mangle: func(t *testing.T, dir string) {
			if err := os.Chmod(aakFilePath(dir), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "0640 file", mangle: func(t *testing.T, dir string) {
			if err := os.Chmod(aakFilePath(dir), 0o640); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "symlinked file", mangle: func(t *testing.T, dir string) {
			p := aakFilePath(dir)
			if err := os.Rename(p, p+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(p+".real", p); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "0755 directory", openFails: true, mangle: func(t *testing.T, dir string) {
			if err := os.Chmod(filepath.Join(dir, "org-bearer"), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer keyring.MockInit()
			dir := t.TempDir()
			_ = seedAAKeyFile(t, dir)
			tc.mangle(t, dir)
			st, err := OpenAgentAccessKeyStoreIn(aakTestService, dir, quietLogger())
			if tc.openFails {
				if !errors.Is(err, ErrAgentAccessKeychainUnavailable) || st != nil {
					t.Fatalf("open = %v, %v; want ErrAgentAccessKeychainUnavailable", st, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if _, err := st.LoadAgentAccessKey(); err == nil || errors.Is(err, ErrNoSecret) {
				t.Fatalf("load of a refused file = %v, want a refusal", err)
			}
		})
	}
}

// TestAgentAccessKeyClearRemovesBoth: Clear removes the keychain record AND
// the file, whichever backend is active; a second Clear is a no-op.
func TestAgentAccessKeyClearRemovesBoth(t *testing.T) {
	skipIfNoFileFallback(t)
	defer keyring.MockInit()
	dir := t.TempDir()
	_ = seedAAKeyFile(t, dir)
	keyring.MockInit()
	_ = seedAAKeyKeychain(t)
	st, err := OpenAgentAccessKeyStoreIn(aakTestService, dir, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := st.ClearAgentAccessKey(); err != nil {
			t.Fatalf("clear #%d: %v", i+1, err)
		}
	}
	if _, err := keyring.Get(aakTestService, recAgentAccessKey); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("keychain record survived clear: %v", err)
	}
	if _, err := os.Lstat(aakFilePath(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("key file survived clear: %v", err)
	}
}

// TestAgentAccessKeyFallbackWarnsOnce: the downgrade WARN names the path
// (never the key) and fires once across invocations (sentinel), re-arming
// after the keychain is back in use.
func TestAgentAccessKeyFallbackWarnsOnce(t *testing.T) {
	skipIfNoFileFallback(t)
	defer keyring.MockInit()
	dir := t.TempDir()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	keyring.MockInitWithError(errors.New("no secret service"))
	for i := 0; i < 3; i++ {
		st, err := OpenAgentAccessKeyStoreIn(aakTestService, dir, logger)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if err := st.SaveAgentAccessKey(newAAKey(t)); err != nil {
				t.Fatal(err)
			}
		}
	}
	out := buf.String()
	if n := strings.Count(out, "falling back to 0600 file store"); n != 1 {
		t.Fatalf("WARN count = %d, want 1:\n%s", n, out)
	}
	if !strings.Contains(out, aakFilePath(dir)) || !strings.Contains(out, "level=WARN") {
		t.Fatalf("WARN does not name the path at WARN level:\n%s", out)
	}
	raw, _ := os.ReadFile(aakFilePath(dir))
	body := strings.TrimPrefix(string(raw), agentAccessKeyEnvelope+":"+DefaultAgentAccessKeyAlg+":")
	if strings.Contains(out, body) {
		t.Fatal("the WARN leaked key material")
	}
	// Keychain back and the file cleared -> sentinel removed -> re-armed.
	keyring.MockInit()
	st, err := OpenAgentAccessKeyStoreIn(aakTestService, dir, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ClearAgentAccessKey(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAgentAccessKeyStoreIn(aakTestService, dir, logger); err != nil {
		t.Fatal(err)
	}
	keyring.MockInitWithError(errors.New("no secret service"))
	if _, err := OpenAgentAccessKeyStoreIn(aakTestService, dir, logger); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(buf.String(), "falling back to 0600 file store"); n != 2 {
		t.Fatalf("WARN count after re-arm = %d, want 2", n)
	}
}

// TestUnenrollClearsAgentAccessKey (ledger AA-5): Unenroll removes the
// agent-access key - keychain record and file - through the real bearer
// store's location, with or without an injected key slot.
func TestUnenrollClearsAgentAccessKey(t *testing.T) {
	skipIfNoFileFallback(t)
	tests := []struct {
		name     string
		keychain bool // bearer + key store backend
		inject   bool // SetAgentAccessKeyStore wired
	}{
		{name: "file backends, slot not injected", keychain: false, inject: false},
		{name: "file backends, slot injected", keychain: false, inject: true},
		{name: "keychain backends, slot not injected", keychain: true, inject: false},
		{name: "keychain backends, slot injected", keychain: true, inject: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer keyring.MockInit()
			if tc.keychain {
				keyring.MockInit()
			} else {
				keyring.MockInitWithError(errors.New("no secret service"))
			}
			dir := t.TempDir()
			s := newAgentStore(t)
			bs := OpenBearerStore(aakTestService, dir, quietLogger())
			if err := bs.SaveBearer("bearer-xyz"); err != nil {
				t.Fatal(err)
			}
			if err := bs.SaveAgentKey(newTestKey(t)); err != nil {
				t.Fatal(err)
			}
			keys, err := OpenAgentAccessKeyStoreIn(aakTestService, dir, quietLogger())
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := EnsureAgentAccessKey(keys); err != nil {
				t.Fatal(err)
			}
			if err := s.WriteEnrolment(context.Background(), store.Enrolment{
				OrgID: "org-1", OrgName: "Acme", OrgServerURL: "https://org.acme.example",
				UserID: "scim-42", UserEmail: "dev@acme.example", BearerKeyID: "k",
			}); err != nil {
				t.Fatal(err)
			}
			c := newTestClient(t, s, bs)
			if tc.inject {
				c.SetAgentAccessKeyStore(keys)
			}
			if err := c.Unenroll(context.Background()); err != nil {
				t.Fatalf("Unenroll: %v", err)
			}
			if _, err := keys.LoadAgentAccessKey(); !errors.Is(err, ErrNoSecret) {
				t.Fatalf("agent-access key survived unenrol: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(dir, "org-bearer", aakTestService+"."+recAgentAccessKey)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("key file survived unenrol: %v", err)
			}
			if tc.keychain {
				if _, err := keyring.Get(aakTestService, recAgentAccessKey); !errors.Is(err, keyring.ErrNotFound) {
					t.Fatalf("keychain record survived unenrol: %v", err)
				}
			}
		})
	}
}
