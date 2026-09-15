package cloudcred

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	keyring "github.com/zalando/go-keyring"
)

// ServiceName is the keychain/file service identifier for personal-cloud
// credentials. It is deliberately distinct from the org bearer service so a
// personal token can never be confused with an org bearer (amendment §3.4).
const ServiceName = "sbo-cloud-credential-v1"

// Record names stored under ServiceName.
const (
	recWorkOSRefresh = "workos-refresh"     // WorkOS rotating refresh material (string)
	recDeviceKey     = "device-signing-key" // base64(std) of the Ed25519 private key
	recAPIToken      = "sbo-api-token"      //nolint:gosec // G101: credential-store RECORD NAME (a keychain key), not a credential value
	recProbe         = "__sbo_cloud_probe__"
)

// scopedRecords declares, per record, whether OpenForHost scopes it to the
// host: the API token and WorkOS refresh material differ per cloud estate
// (a node signed into staging and production estates holds two of each), so
// they scope. The device signing key does not: it is one device identity,
// registered with each estate on exchange, so every host must see the same
// key.
var scopedRecords = map[string]bool{
	recAPIToken:      true,
	recWorkOSRefresh: true,
	recDeviceKey:     false,
}

// recordName is the ONE place that turns a record + host into the name a
// backend stores under (a keychain key, or a file-name suffix). An empty
// host — Open, i.e. OpenForHost(dir, "", logger) — is today's single-slot
// behaviour and never appends a suffix. A record scopedRecords marks as
// shared (the device signing key) is never suffixed even when host != "".
func recordName(rec, host string) string {
	if host == "" || !scopedRecords[rec] {
		return rec
	}
	return rec + "@" + host
}

// ErrNotFound is returned by Load* when nothing has been stored yet.
var ErrNotFound = errors.New("cloudcred: credential not present")

// ErrInsecureFallbackUnavailable is returned by every method of the store
// Open selects when the OS keychain is unavailable AND this platform build's
// file fallback has not been verified secure (fileFallbackSecure() == false
// — currently every non-unix build; see cred_other.go). Writing the WorkOS
// refresh material, API bearer token, or Ed25519 device signing key to a
// plaintext file without verifying the DACL is current-user-only, and
// without refusing a reparse point, is worse than refusing outright: a local
// principal able to read/replace the path, or one who wins the Lstat-to-open
// race, can steal the whole cloud identity — and PoP protects nothing once
// its own signing key is stolen along with it. So this platform build fails
// closed instead. See FF2, docs/audits/cloud-intelligence-shipped-code-sol-
// review-2026-08-31.md.
var ErrInsecureFallbackUnavailable = errors.New(
	"cloudcred: secure credential storage is unavailable on this platform build " +
		"(the OS keychain is unreachable and the plaintext file fallback has no " +
		"verified ACL/reparse-point protection on this platform); the cloud CLI " +
		"cannot store credentials here — retry once the OS keychain (e.g. Windows " +
		"Credential Manager) is reachable",
)

// Store persists the three personal-cloud secrets outside the agent DB. All
// methods are safe for concurrent use across processes via the underlying
// backend's own atomicity guarantees (keychain item replace; file rename).
type Store interface {
	// SaveWorkOSRefresh persists the WorkOS refresh material.
	SaveWorkOSRefresh(refresh string) error
	// LoadWorkOSRefresh returns the stored WorkOS refresh material, or
	// ErrNotFound when the user has not logged in.
	LoadWorkOSRefresh() (string, error)

	// SaveDeviceKey persists the device Ed25519 private key.
	SaveDeviceKey(key ed25519.PrivateKey) error
	// LoadDeviceKey returns the device Ed25519 private key, or ErrNotFound when
	// no device key has been created yet.
	LoadDeviceKey() (ed25519.PrivateKey, error)

	// SaveAPIToken persists the current short-lived SuperBased API token.
	SaveAPIToken(token string) error
	// LoadAPIToken returns the current short-lived SuperBased API token, or
	// ErrNotFound when none has been exchanged (or it was cleared).
	LoadAPIToken() (string, error)

	// Clear removes all three secrets (logout/device-revoke). Absence is not an
	// error.
	Clear() error

	// Backend names the active store ("keychain" or "file") for diagnostics.
	Backend() string

	// SecurityDiagnostic returns a human-readable degraded-security warning, or
	// "" when the active backend provides OS-backed protection. The CLI surfaces
	// a non-empty value to the user.
	SecurityDiagnostic() string
}

// Open selects a backend for personal-cloud credentials, in the legacy
// single-slot shape (no host scoping). It is a thin wrapper over
// OpenForHost(fallbackDir, "", logger); see OpenForHost for the full
// contract.
func Open(fallbackDir string, logger *slog.Logger) Store {
	return OpenForHost(fallbackDir, "", logger)
}

// OpenForHost selects a backend for personal-cloud credentials, scoped to
// host: the bare, lower-cased host of the cloud base URL a node is currently
// configured against (e.g. "cloud.superbased.app" or
// "staging-cloud.superbased.app"). It probes the OS keychain once; on a
// successful round-trip it returns a keychain-backed store. Otherwise it
// falls back to selectFallbackStore, which is a hardened 0600 file store
// rooted at <fallbackDir>/cloud-cred ONLY on a platform build whose file
// fallback has verified owner+symlink protections (fileFallbackSecure();
// unix today) — on every other platform build it fails closed
// (failClosedStore) rather than write an unverified plaintext file. A nil
// logger is tolerated (slog.Default is used). OpenForHost performs no
// network I/O.
//
// host == "" reproduces Open's legacy single-slot behaviour: every record
// name is unscoped. A non-empty host scopes the API token and WorkOS refresh
// material (recordName / scopedRecords) but never the device signing key,
// which is shared across every host.
//
// # Legacy adoption
//
// The API token and WorkOS refresh material may already exist under the
// legacy unscoped record name from before per-host scoping shipped. On a
// host-scoped store, LoadAPIToken/LoadWorkOSRefresh adopt that legacy value
// ONE TIME when the scoped record is absent: they return the legacy value
// AND migrate it (save under the scoped name, then delete the unscoped
// record). Adoption fires for whichever host happens to read first — that is
// the host the node was configured for when the legacy sign-in happened (in
// practice, the operator's production estate) — and every other host finds
// the legacy record already gone.
func OpenForHost(fallbackDir, host string, logger *slog.Logger) Store {
	if logger == nil {
		logger = slog.Default()
	}
	storeDir := filepath.Join(fallbackDir, "cloud-cred")
	sentinel := filepath.Join(storeDir, ".keychain-unavailable")
	if keychainUsable() {
		_ = os.Remove(sentinel)
		return &keychainStore{host: host}
	}
	secure := fileFallbackSecure()
	store := selectFallbackStore(secure, storeDir, host)
	if !secure {
		logger.Warn(
			"cloud credentials: OS keychain unavailable and this platform build's file "+
				"fallback has no verified ACL/reparse-point protection; failing closed "+
				"instead of storing credentials in an unverified plaintext file",
			"service", ServiceName,
		)
		return store
	}
	if _, err := os.Stat(sentinel); err != nil {
		logger.Warn(
			"cloud credentials: OS keychain unavailable, falling back to hardened 0600 file store",
			"service", ServiceName, "dir", storeDir,
			"note", "secrets are stored without OS-backed encryption; this warning is suppressed on subsequent invocations",
		)
		_ = os.MkdirAll(storeDir, 0o700)
		_ = os.WriteFile(sentinel, []byte("1"), 0o600)
	}
	return store
}

// selectFallbackStore is the pure decision OpenForHost delegates to once the
// OS keychain has proven unusable: is the platform's plaintext file fallback
// permitted, or must credential storage fail closed? It is factored out of
// OpenForHost (which also owns logging/sentinel side effects) so the
// decision is unit-testable on any host OS without needing a real Windows
// machine — exercise it directly with secure=true and secure=false; see
// TestSelectFallbackStore* in cred_test.go. secure is fileFallbackSecure()'s
// answer for the host platform build in production use. host is threaded
// through unchanged to the returned fileStore; it plays no part in the
// secure/insecure decision.
func selectFallbackStore(secure bool, dir, host string) Store {
	if secure {
		return &fileStore{dir: dir, host: host}
	}
	return &failClosedStore{}
}

// failClosedStore is what selectFallbackStore returns when this platform
// build's file fallback is not verified secure (fileFallbackSecure() ==
// false). Every credential-bearing method refuses with
// ErrInsecureFallbackUnavailable instead of silently persisting a secret to
// an unverified plaintext file (FF2).
type failClosedStore struct{}

func (failClosedStore) Backend() string { return "unavailable" }

// SecurityDiagnostic honestly reports the fail-closed posture: unlike
// fileStore (which reports a degraded-but-functioning backend),
// failClosedStore stores nothing at all.
func (failClosedStore) SecurityDiagnostic() string {
	return "cloud credential storage is disabled on this platform build: the OS " +
		"keychain is unreachable and the plaintext file fallback has no verified " +
		"ACL/reparse-point protection, so credentials are refused rather than " +
		"written insecurely (fail-closed)"
}

func (failClosedStore) SaveWorkOSRefresh(string) error { return ErrInsecureFallbackUnavailable }

func (failClosedStore) LoadWorkOSRefresh() (string, error) {
	return "", ErrInsecureFallbackUnavailable
}

func (failClosedStore) SaveDeviceKey(ed25519.PrivateKey) error {
	return ErrInsecureFallbackUnavailable
}

func (failClosedStore) LoadDeviceKey() (ed25519.PrivateKey, error) {
	return nil, ErrInsecureFallbackUnavailable
}

func (failClosedStore) SaveAPIToken(string) error { return ErrInsecureFallbackUnavailable }

func (failClosedStore) LoadAPIToken() (string, error) {
	return "", ErrInsecureFallbackUnavailable
}

// Clear is a no-op success: failClosedStore never persisted anything, and
// Store.Clear documents that absence is not an error.
func (failClosedStore) Clear() error { return nil }

// keychainUsable probes the keyring with a throwaway record. A full
// set/get/delete cycle is the only reliable cross-platform availability test.
func keychainUsable() bool {
	if err := keyring.Set(ServiceName, recProbe, "1"); err != nil {
		return false
	}
	got, err := keyring.Get(ServiceName, recProbe)
	_ = keyring.Delete(ServiceName, recProbe)
	return err == nil && got == "1"
}

// --- keychain-backed store -------------------------------------------------

// keychainStore is scoped to host (see recordName / scopedRecords); host =
// "" reproduces the legacy single-slot behaviour.
type keychainStore struct {
	host string
}

func (s *keychainStore) Backend() string            { return "keychain" }
func (s *keychainStore) SecurityDiagnostic() string { return "" }

func (s *keychainStore) SaveWorkOSRefresh(refresh string) error {
	if err := s.setScoped(recWorkOSRefresh, refresh); err != nil {
		return fmt.Errorf("cloudcred.SaveWorkOSRefresh: %w", err)
	}
	return nil
}

func (s *keychainStore) LoadWorkOSRefresh() (string, error) {
	return s.getScoped(recWorkOSRefresh, "LoadWorkOSRefresh")
}

func (s *keychainStore) SaveAPIToken(token string) error {
	if err := s.setScoped(recAPIToken, token); err != nil {
		return fmt.Errorf("cloudcred.SaveAPIToken: %w", err)
	}
	return nil
}

func (s *keychainStore) LoadAPIToken() (string, error) {
	return s.getScoped(recAPIToken, "LoadAPIToken")
}

func (s *keychainStore) SaveDeviceKey(key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("cloudcred.SaveDeviceKey: key is %d bytes, want %d", len(key), ed25519.PrivateKeySize)
	}
	// recordName never scopes recDeviceKey (scopedRecords[recDeviceKey] ==
	// false): one device identity is shared across every host.
	if err := keyring.Set(ServiceName, recordName(recDeviceKey, s.host), base64.StdEncoding.EncodeToString(key)); err != nil {
		return fmt.Errorf("cloudcred.SaveDeviceKey: %w", err)
	}
	return nil
}

func (s *keychainStore) LoadDeviceKey() (ed25519.PrivateKey, error) {
	v, err := s.get(recordName(recDeviceKey, s.host), "LoadDeviceKey")
	if err != nil {
		return nil, err
	}
	return decodeDeviceKey(v)
}

func (s *keychainStore) get(rec, fn string) (string, error) {
	v, err := keyring.Get(ServiceName, rec)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("cloudcred.%s: %w", fn, err)
	}
	return v, nil
}

// getScoped loads rec scoped to s.host, with the one-time legacy adoption
// documented on OpenForHost: when the scoped record is absent, a live
// legacy (unscoped) record is returned AND migrated — saved under the scoped
// name, then the legacy record deleted — so no later reader adopts it again.
func (s *keychainStore) getScoped(rec, fn string) (string, error) {
	scoped := recordName(rec, s.host)
	v, err := s.get(scoped, fn)
	if err == nil {
		return v, nil
	}
	if !errors.Is(err, ErrNotFound) || s.host == "" || !scopedRecords[rec] {
		return "", err
	}
	dir, derr := keychainCoordDir()
	if derr != nil {
		return "", derr
	}
	err = adoptLegacyBundle(dir, s.host,
		func(rec string) (string, error) { return s.get(rec, fn) },
		func(rec, value string) error { return keyring.Set(ServiceName, rec, value) },
		func(rec string) error {
			err := keyring.Delete(ServiceName, rec)
			if errors.Is(err, keyring.ErrNotFound) {
				return ErrNotFound
			}
			return err
		})
	if err != nil {
		return "", err
	}
	return s.get(scoped, fn)
}

func (s *keychainStore) setScoped(rec, value string) error {
	dir, err := keychainCoordDir()
	if err != nil {
		return err
	}
	return withCredentialLock(dir, func() error { return keyring.Set(ServiceName, recordName(rec, s.host), value) })
}

// Clear removes this host's scoped API token and WorkOS refresh, the legacy
// unscoped records if still present, and the device signing key. The device
// key is shared across hosts, so Clear is a full device reset (logout /
// device-revoke) — it does not reference-count hosts, and clearing one
// host's store clears the device identity for every host.
func (s *keychainStore) Clear() error {
	dir, err := keychainCoordDir()
	if err != nil {
		return err
	}
	return withCredentialLock(dir, s.clearLocked)
}

func (s *keychainStore) clearLocked() error {
	recs := []string{recDeviceKey, recWorkOSRefresh, recAPIToken}
	if s.host != "" {
		recs = append(recs, recordName(recWorkOSRefresh, s.host), recordName(recAPIToken, s.host))
	}
	var errs []error
	for _, rec := range recs {
		if err := keyring.Delete(ServiceName, rec); err != nil && !errors.Is(err, keyring.ErrNotFound) {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("cloudcred.Clear: %w", errors.Join(errs...))
	}
	return nil
}

// decodeDeviceKey validates a stored Ed25519 private key.
func decodeDeviceKey(v string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("cloudcred: decode device key: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("cloudcred: device key wrong size: got %d want %d", len(raw), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(raw), nil
}
