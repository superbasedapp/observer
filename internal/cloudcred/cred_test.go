package cloudcred

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// newFileStore returns a hardened file store rooted in a fresh 0700 temp dir.
func newFileStore(t *testing.T) *fileStore {
	t.Helper()
	return &fileStore{dir: filepath.Join(t.TempDir(), "cloud-cred")}
}

func TestFileStoreRoundTrip(t *testing.T) {
	s := newFileStore(t)

	// Nothing stored yet.
	if _, err := s.LoadAPIToken(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("LoadAPIToken empty = %v, want ErrNotFound", err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if err := s.SaveWorkOSRefresh("refresh-abc"); err != nil {
		t.Fatalf("SaveWorkOSRefresh: %v", err)
	}
	if err := s.SaveDeviceKey(priv); err != nil {
		t.Fatalf("SaveDeviceKey: %v", err)
	}
	if err := s.SaveAPIToken("api-xyz"); err != nil {
		t.Fatalf("SaveAPIToken: %v", err)
	}

	if got, err := s.LoadWorkOSRefresh(); err != nil || got != "refresh-abc" {
		t.Fatalf("LoadWorkOSRefresh = %q,%v", got, err)
	}
	if got, err := s.LoadAPIToken(); err != nil || got != "api-xyz" {
		t.Fatalf("LoadAPIToken = %q,%v", got, err)
	}
	gotKey, err := s.LoadDeviceKey()
	if err != nil {
		t.Fatalf("LoadDeviceKey: %v", err)
	}
	if !gotKey.Public().(ed25519.PublicKey).Equal(pub) {
		t.Fatal("loaded device key does not match saved key")
	}

	// Mode is 0600.
	fi, err := os.Stat(s.path(recAPIToken))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("credential mode = %#o, want 0600", fi.Mode().Perm())
	}

	if err := s.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if _, err := s.LoadAPIToken(); !errors.Is(err, ErrNotFound) {
		t.Errorf("after Clear LoadAPIToken = %v, want ErrNotFound", err)
	}
}

func TestFileStoreSymlinkRefusedOnRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	s := newFileStore(t)
	if err := s.ensureDir(); err != nil {
		t.Fatalf("ensureDir: %v", err)
	}
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "attacker-secret")
	if err := os.WriteFile(outside, []byte("attacker-controlled"), 0o600); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	if err := os.Symlink(outside, s.path(recAPIToken)); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := s.LoadAPIToken(); err == nil {
		t.Fatal("LoadAPIToken followed a symlink; must refuse")
	}
}

func TestFileStoreSymlinkRefusedOnWrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	s := newFileStore(t)
	if err := s.ensureDir(); err != nil {
		t.Fatalf("ensureDir: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(outside, []byte("old"), 0o600); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	if err := os.Symlink(outside, s.path(recAPIToken)); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := s.SaveAPIToken("new"); err == nil {
		t.Fatal("SaveAPIToken replaced a symlink target; must refuse")
	}
	// The outside file must not have been written through the symlink.
	b, _ := os.ReadFile(outside)
	if string(b) != "old" {
		t.Fatalf("symlink write leaked to %q: %q", outside, b)
	}
}

func TestFileStorePermissiveFileRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits do not apply on Windows")
	}
	s := newFileStore(t)
	if err := s.ensureDir(); err != nil {
		t.Fatalf("ensureDir: %v", err)
	}
	// A pre-created, group/world-readable credential file must be refused.
	if err := os.WriteFile(s.path(recAPIToken), []byte("api-xyz"), 0o644); err != nil {
		t.Fatalf("write permissive: %v", err)
	}
	if _, err := s.LoadAPIToken(); err == nil {
		t.Fatal("LoadAPIToken accepted a 0644 file; must refuse")
	}
}

func TestFileStorePermissiveDirRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits do not apply on Windows")
	}
	dir := filepath.Join(t.TempDir(), "loose")
	if err := os.MkdirAll(dir, 0o777); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// MkdirAll on an existing dir won't tighten it; ensureDir must reject 0777.
	s := &fileStore{dir: dir}
	if err := s.SaveAPIToken("x"); err == nil {
		t.Fatal("SaveAPIToken into a 0777 dir; must refuse")
	}
}

func TestFileStoreCrashMidWriteLeavesOldValue(t *testing.T) {
	s := newFileStore(t)
	if err := s.SaveAPIToken("v1"); err != nil {
		t.Fatalf("SaveAPIToken v1: %v", err)
	}
	// Simulate a crash that left a stale temp file behind (temp created, process
	// died before rename). The old value must remain readable, and a later write
	// must still succeed.
	stale := s.path(recAPIToken) + ".tmp.deadbeef"
	if err := os.WriteFile(stale, []byte("garbage-partial"), 0o600); err != nil {
		t.Fatalf("write stale temp: %v", err)
	}
	if got, err := s.LoadAPIToken(); err != nil || got != "v1" {
		t.Fatalf("after stale temp LoadAPIToken = %q,%v, want v1", got, err)
	}
	if err := s.SaveAPIToken("v2"); err != nil {
		t.Fatalf("SaveAPIToken v2: %v", err)
	}
	if got, err := s.LoadAPIToken(); err != nil || got != "v2" {
		t.Fatalf("LoadAPIToken = %q,%v, want v2", got, err)
	}
}

func TestFileStoreConcurrentRotation(t *testing.T) {
	s := newFileStore(t)
	if err := s.SaveAPIToken("seed"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	const writers = 12
	valid := map[string]bool{"seed": true}
	var mu sync.Mutex
	var wg sync.WaitGroup
	errCh := make(chan error, writers)
	for i := 0; i < writers; i++ {
		v := fmt.Sprintf("tok-%02d", i)
		mu.Lock()
		valid[v] = true
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.SaveAPIToken(v); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent SaveAPIToken: %v", err)
	}
	// The final value is always a complete written value, never truncated.
	got, err := s.LoadAPIToken()
	if err != nil {
		t.Fatalf("LoadAPIToken: %v", err)
	}
	if !valid[got] {
		t.Fatalf("LoadAPIToken = %q, not one of the written values (torn write?)", got)
	}
	// No temp files should be left behind.
	entries, _ := os.ReadDir(s.dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

func TestFileStoreSecurityDiagnostic(t *testing.T) {
	s := newFileStore(t)
	if s.Backend() != "file" {
		t.Errorf("Backend = %q, want file", s.Backend())
	}
	if s.SecurityDiagnostic() == "" {
		t.Error("file backend must report a non-empty degraded-security diagnostic")
	}
}

// TestSelectFallbackStoreFailsClosedWhenInsecure is the FF2 regression: on a
// platform build whose file fallback has no verified ACL/reparse-point
// protection (secure=false — every non-unix build today, see
// fileFallbackSecure in cred_other.go), Open must never silently persist the
// WorkOS refresh material, API bearer token, or Ed25519 device signing key to
// an unverified plaintext file. selectFallbackStore is the pure decision
// function Open delegates to, so this is exercised here without needing a
// real Windows host — the GOOS=windows build gate proves the platform wiring
// compiles and picks secure=false there (fileFallbackSecure in
// cred_other.go).
func TestSelectFallbackStoreFailsClosedWhenInsecure(t *testing.T) {
	s := selectFallbackStore(false, filepath.Join(t.TempDir(), "cloud-cred"), "")

	if _, ok := s.(*fileStore); ok {
		t.Fatal("selectFallbackStore(false, ...) returned *fileStore; must never select the unverified plaintext fallback")
	}
	if got := s.Backend(); got != "unavailable" {
		t.Errorf("Backend() = %q, want %q", got, "unavailable")
	}
	if diag := s.SecurityDiagnostic(); !strings.Contains(diag, "fail-closed") {
		t.Errorf("SecurityDiagnostic() = %q, want it to mention fail-closed", diag)
	}

	if err := s.SaveWorkOSRefresh("refresh"); !errors.Is(err, ErrInsecureFallbackUnavailable) {
		t.Errorf("SaveWorkOSRefresh = %v, want ErrInsecureFallbackUnavailable", err)
	}
	if _, err := s.LoadWorkOSRefresh(); !errors.Is(err, ErrInsecureFallbackUnavailable) {
		t.Errorf("LoadWorkOSRefresh = %v, want ErrInsecureFallbackUnavailable", err)
	}
	if err := s.SaveAPIToken("token"); !errors.Is(err, ErrInsecureFallbackUnavailable) {
		t.Errorf("SaveAPIToken = %v, want ErrInsecureFallbackUnavailable", err)
	}
	if _, err := s.LoadAPIToken(); !errors.Is(err, ErrInsecureFallbackUnavailable) {
		t.Errorf("LoadAPIToken = %v, want ErrInsecureFallbackUnavailable", err)
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if err := s.SaveDeviceKey(priv); !errors.Is(err, ErrInsecureFallbackUnavailable) {
		t.Errorf("SaveDeviceKey = %v, want ErrInsecureFallbackUnavailable", err)
	}
	if _, err := s.LoadDeviceKey(); !errors.Is(err, ErrInsecureFallbackUnavailable) {
		t.Errorf("LoadDeviceKey = %v, want ErrInsecureFallbackUnavailable", err)
	}
	// Nothing was ever stored, so Clear must still succeed (absence is not an
	// error, per the Store.Clear contract).
	if err := s.Clear(); err != nil {
		t.Errorf("Clear = %v, want nil", err)
	}
}

// TestSelectFallbackStoreUsesFileStoreWhenSecure is the secure=true half of
// the same decision: a platform build whose file fallback IS verified (unix)
// must keep using the hardened fileStore, unchanged by the FF2 fix.
func TestSelectFallbackStoreUsesFileStoreWhenSecure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cloud-cred")
	s := selectFallbackStore(true, dir, "cloud.superbased.app")

	fs, ok := s.(*fileStore)
	if !ok {
		t.Fatalf("selectFallbackStore(true, ...) = %T, want *fileStore", s)
	}
	if fs.dir != dir {
		t.Errorf("fileStore.dir = %q, want %q", fs.dir, dir)
	}
	if fs.host != "cloud.superbased.app" {
		t.Errorf("fileStore.host = %q, want %q", fs.host, "cloud.superbased.app")
	}
}

// TestFileFallbackSecureMatchesHostPlatformContract pins fileFallbackSecure's
// per-platform answer against the CI-P2 contract: true only where the
// protections it gates (O_NOFOLLOW symlink refusal + real POSIX ownership
// checks, cred_unix.go) are actually implemented. A Windows build must report
// false so Open fails closed (cred_other.go).
func TestFileFallbackSecureMatchesHostPlatformContract(t *testing.T) {
	if runtime.GOOS == "windows" {
		if fileFallbackSecure() {
			t.Fatal("fileFallbackSecure() = true on windows; must be false until DACL/reparse-point verification ships")
		}
		return
	}
	if !fileFallbackSecure() {
		t.Fatal("fileFallbackSecure() = false on a unix build; want true (O_NOFOLLOW + real ownership checks apply)")
	}
}

// --- per-host scoping (OpenForHost) -----------------------------------------

const (
	testProdHost    = "cloud.superbased.app"
	testStagingHost = "staging-cloud.superbased.app"
)

func TestRecordNameTable(t *testing.T) {
	tests := []struct {
		name string
		rec  string
		host string
		want string
	}{
		{"api token unscoped", recAPIToken, "", recAPIToken},
		{"api token scoped", recAPIToken, testProdHost, recAPIToken + "@" + testProdHost},
		{"refresh unscoped", recWorkOSRefresh, "", recWorkOSRefresh},
		{"refresh scoped", recWorkOSRefresh, testProdHost, recWorkOSRefresh + "@" + testProdHost},
		{"device key never scoped, host set", recDeviceKey, testProdHost, recDeviceKey},
		{"device key never scoped, no host", recDeviceKey, "", recDeviceKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := recordName(tt.rec, tt.host); got != tt.want {
				t.Errorf("recordName(%q, %q) = %q, want %q", tt.rec, tt.host, got, tt.want)
			}
		})
	}
}

// TestFileStoreHostScopedTokensAreIsolated proves the API token and WorkOS
// refresh material do not cross host boundaries: a node signed into staging
// must never see production's token, and vice versa.
func TestFileStoreHostScopedTokensAreIsolated(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cloud-cred")
	prod := &fileStore{dir: dir, host: testProdHost}
	staging := &fileStore{dir: dir, host: testStagingHost}

	if err := prod.SaveAPIToken("prod-token"); err != nil {
		t.Fatalf("prod SaveAPIToken: %v", err)
	}
	if err := prod.SaveWorkOSRefresh("prod-refresh"); err != nil {
		t.Fatalf("prod SaveWorkOSRefresh: %v", err)
	}

	if _, err := staging.LoadAPIToken(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("staging LoadAPIToken = %v, want ErrNotFound (must not see prod's token)", err)
	}
	if _, err := staging.LoadWorkOSRefresh(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("staging LoadWorkOSRefresh = %v, want ErrNotFound (must not see prod's refresh)", err)
	}

	if err := staging.SaveAPIToken("staging-token"); err != nil {
		t.Fatalf("staging SaveAPIToken: %v", err)
	}
	if got, err := prod.LoadAPIToken(); err != nil || got != "prod-token" {
		t.Fatalf("prod LoadAPIToken after staging write = %q,%v, want unchanged prod-token", got, err)
	}
	if got, err := staging.LoadAPIToken(); err != nil || got != "staging-token" {
		t.Fatalf("staging LoadAPIToken = %q,%v, want staging-token", got, err)
	}
}

// TestFileStoreHostScopedDeviceKeyIsShared proves the device signing key is
// the SAME across every host: it is one device identity, registered with
// each estate on exchange, not a per-estate secret.
func TestFileStoreHostScopedDeviceKeyIsShared(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cloud-cred")
	prod := &fileStore{dir: dir, host: testProdHost}
	staging := &fileStore{dir: dir, host: testStagingHost}

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if err := prod.SaveDeviceKey(priv); err != nil {
		t.Fatalf("SaveDeviceKey: %v", err)
	}
	got, err := staging.LoadDeviceKey()
	if err != nil {
		t.Fatalf("staging LoadDeviceKey = %v, want the shared device key visible", err)
	}
	if !got.Public().(ed25519.PublicKey).Equal(priv.Public().(ed25519.PublicKey)) {
		t.Fatal("staging saw a different device key than prod saved; device identity must be shared across hosts")
	}
}

// TestFileStoreLegacyAdoptionMigratesExactlyOnce proves the OpenForHost doc
// comment's adoption rule: whichever host reads first adopts the legacy
// unscoped record (migrating it to its own scoped name and deleting the
// unscoped one), and no other host adopts it afterwards.
func TestFileStoreLegacyAdoptionMigratesExactlyOnce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cloud-cred")
	legacy := &fileStore{dir: dir} // host == "" — a pre-scoping sign-in.
	if err := legacy.SaveAPIToken("legacy-token"); err != nil {
		t.Fatalf("seed legacy token: %v", err)
	}
	if err := legacy.SaveWorkOSRefresh("legacy-refresh"); err != nil {
		t.Fatalf("seed legacy refresh: %v", err)
	}

	prod := &fileStore{dir: dir, host: testProdHost}
	if got, err := prod.LoadAPIToken(); err != nil || got != "legacy-token" {
		t.Fatalf("prod LoadAPIToken (adoption) = %q,%v, want legacy-token", got, err)
	}
	if got, err := prod.LoadWorkOSRefresh(); err != nil || got != "legacy-refresh" {
		t.Fatalf("prod LoadWorkOSRefresh (adoption) = %q,%v, want legacy-refresh", got, err)
	}

	// The legacy files are gone after adoption.
	if _, err := os.Stat(legacy.path(recAPIToken)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy API token file still present after adoption: err=%v", err)
	}
	if _, err := os.Stat(legacy.path(recWorkOSRefresh)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy refresh file still present after adoption: err=%v", err)
	}

	// A second host must NOT adopt — the legacy record is already consumed.
	staging := &fileStore{dir: dir, host: testStagingHost}
	if _, err := staging.LoadAPIToken(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("staging LoadAPIToken = %v, want ErrNotFound (legacy already adopted by prod)", err)
	}
	if _, err := staging.LoadWorkOSRefresh(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("staging LoadWorkOSRefresh = %v, want ErrNotFound (legacy already adopted by prod)", err)
	}

	// The scoped record persists for further reads.
	if got, err := prod.LoadAPIToken(); err != nil || got != "legacy-token" {
		t.Fatalf("prod LoadAPIToken (post-adoption) = %q,%v, want legacy-token", got, err)
	}
}

// TestFileStoreHostScopedClearRemovesScopedLegacyAndDeviceKey proves Clear's
// documented scope: a host-scoped store's Clear removes that host's two
// scoped records, any still-present legacy unscoped records, AND the shared
// device key (a full device reset).
func TestFileStoreHostScopedClearRemovesScopedLegacyAndDeviceKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cloud-cred")
	prod := &fileStore{dir: dir, host: testProdHost}
	if err := prod.SaveAPIToken("prod-token"); err != nil {
		t.Fatalf("SaveAPIToken: %v", err)
	}
	if err := prod.SaveWorkOSRefresh("prod-refresh"); err != nil {
		t.Fatalf("SaveWorkOSRefresh: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if err := prod.SaveDeviceKey(priv); err != nil {
		t.Fatalf("SaveDeviceKey: %v", err)
	}
	// A stray legacy (unscoped) record, as if adoption never ran for it.
	legacy := &fileStore{dir: dir}
	if err := legacy.SaveAPIToken("legacy-token"); err != nil {
		t.Fatalf("seed legacy: %v", err)
	}

	if err := prod.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}

	if _, err := prod.LoadAPIToken(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("prod LoadAPIToken after Clear = %v, want ErrNotFound", err)
	}
	if _, err := prod.LoadWorkOSRefresh(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("prod LoadWorkOSRefresh after Clear = %v, want ErrNotFound", err)
	}
	if _, err := prod.LoadDeviceKey(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("LoadDeviceKey after Clear = %v, want ErrNotFound (device reset)", err)
	}
	if _, err := os.Stat(legacy.path(recAPIToken)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("legacy API token file still present after Clear")
	}
}

// TestFileStoreOpenForHostEmptyHostIsLegacyShape proves host == "" is
// byte-for-byte the pre-scoping behaviour: no "@" suffix is ever applied.
func TestFileStoreOpenForHostEmptyHostIsLegacyShape(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cloud-cred")
	s := &fileStore{dir: dir}
	if err := s.SaveAPIToken("tok"); err != nil {
		t.Fatalf("SaveAPIToken: %v", err)
	}
	want := filepath.Join(dir, ServiceName+"."+recAPIToken)
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("legacy-shaped file missing at %s: %v", want, err)
	}
}

// TestFileStoreHostlessClearWipesEveryHost pins the full-wipe semantics of a
// Clear on the legacy (host-less) store: an `observer cloud logout` that
// cannot resolve a host removes every host's scoped records too, plus the
// legacy records and the device key - nothing of the service survives.
func TestFileStoreHostlessClearWipesEveryHost(t *testing.T) {
	dir := t.TempDir()
	a := OpenForHost(dir, "a.example", nil)
	b := OpenForHost(dir, "b.example", nil)
	if err := a.SaveAPIToken("tok-a"); err != nil {
		t.Fatal(err)
	}
	if err := b.SaveWorkOSRefresh("ref-b"); err != nil {
		t.Fatal(err)
	}
	if err := Open(dir, nil).Clear(); err != nil {
		t.Fatalf("host-less Clear: %v", err)
	}
	if _, err := a.LoadAPIToken(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("host a token survived the host-less Clear: %v", err)
	}
	if _, err := b.LoadWorkOSRefresh(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("host b refresh survived the host-less Clear: %v", err)
	}
}
