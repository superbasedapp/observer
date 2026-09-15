package orgclient

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	keyring "github.com/zalando/go-keyring"
)

// keyring record names stored under the configured service (KeychainID).
const (
	recBearer     = "bearer"              // the signed bearer envelope (string)
	recAgentKey   = "agent-signing-key"   // base64(std) of the Ed25519 private key
	recVirtualKey = "gateway-virtual-key" // JSON virtualKeyRecord (P5a, AI Gateway auth-substitution)
	// recBreakGlassLeases is declared in breakglass.go (the fourth, optional slot).
	recProbe = "__sbo_probe__" // backend-availability probe
)

// ErrNoSecret is returned by Load* when nothing has been stored yet (a
// not-enrolled agent). Callers treat it as "not enrolled", not as a failure.
var ErrNoSecret = errors.New("orgclient: secret not present")

// virtualKeyRecord is the on-disk/keychain shape of the third BearerStore
// slot. Generation pins the record to the routing-generation snapshot
// (internal/proxy) that installed it, so a stale virtual key surviving a
// config reload (or a node restart between an install and its ack) can be
// told apart from the one the currently-live snapshot actually expects.
type virtualKeyRecord struct {
	Key        string `json:"key"`
	Generation uint64 `json:"generation"`
}

// BearerStore persists the agent's local secrets outside the agent DB:
// the server-issued bearer, the agent's Ed25519 signing key, and (P5a) the
// AI Gateway virtual key used to auth-substitute for the developer's own
// provider credential in Gateway Mode (docs/plans/plane-b-dual-mode-gateway-
// rbac-ia-design-2026-08-29.md §2.3, Sol S2). Implementations are either
// OS-keychain-backed or a 0600-mode file fallback.
type BearerStore interface {
	SaveBearer(bearer string) error
	LoadBearer() (string, error)
	SaveAgentKey(key ed25519.PrivateKey) error
	LoadAgentKey() (ed25519.PrivateKey, error)
	// SaveVirtualKey persists the AI Gateway virtual key alongside the
	// routing-generation it was issued for.
	SaveVirtualKey(key string, generation uint64) error
	// LoadVirtualKey returns the stored virtual key and the generation it
	// was saved under. Returns ErrNoSecret when nothing has been saved yet
	// (Gateway Mode not yet provisioned, or cleared by unenrol/rotation).
	LoadVirtualKey() (key string, generation uint64, err error)
	// Clear removes all three secrets (used by unenrol). Absence is not an
	// error.
	Clear() error
	// Backend names the active store ("keychain" or "file") for diagnostics.
	Backend() string
}

// OpenBearerStore selects a backend for the given keychain service id. It
// probes the OS keychain once; if a round-trip succeeds it returns a
// keychain-backed store, otherwise it falls back to a 0600-mode file store
// rooted at fallbackDir. A nil logger is tolerated (slog.Default is used).
//
// Warning hygiene (M4.4 of the 2026-06-02 teams test follow-ups): on the
// FIRST observed downgrade we log a WARN naming the fallback; we then
// touch a sentinel at <fallbackDir>/org-bearer/.keychain-unavailable so
// subsequent CLI invocations (which can be many per session) stay silent.
// If the keychain later becomes available (e.g. the user starts gnome-
// keyring-daemon), keychainUsable() returns true on the next probe, we
// remove the sentinel, and the WARN can fire again on a future downgrade.
func OpenBearerStore(service, fallbackDir string, logger *slog.Logger) BearerStore {
	if logger == nil {
		logger = slog.Default()
	}
	storeDir := filepath.Join(fallbackDir, "org-bearer")
	sentinel := filepath.Join(storeDir, ".keychain-unavailable")
	if keychainUsable(service) {
		// Recovered from a previous downgrade — clear the sentinel so a
		// future downgrade warns again.
		_ = os.Remove(sentinel)
		return &keychainStore{service: service}
	}
	if _, err := os.Stat(sentinel); err != nil {
		logger.Warn(
			"org bearer: OS keychain unavailable, falling back to 0600 file store",
			"service", service, "dir", fallbackDir,
			"note", "this warning is suppressed on subsequent invocations; remove ~/.observer/org-bearer/.keychain-unavailable to re-arm",
		)
		_ = os.MkdirAll(storeDir, 0o700)
		_ = os.WriteFile(sentinel, []byte("1"), 0o600)
	}
	return &fileStore{dir: storeDir, service: service}
}

// keychainUsable probes the keyring with a throwaway record. A full
// set/get/delete cycle is the only reliable cross-platform availability test
// (ErrUnsupportedPlatform alone misses headless Linux without a Secret
// Service). The probe record is always deleted.
func keychainUsable(service string) bool {
	if err := keyring.Set(service, recProbe, "1"); err != nil {
		return false
	}
	got, err := keyring.Get(service, recProbe)
	_ = keyring.Delete(service, recProbe)
	return err == nil && got == "1"
}

// --- keychain-backed store -------------------------------------------------

type keychainStore struct{ service string }

func (s *keychainStore) Backend() string { return "keychain" }

func (s *keychainStore) SaveBearer(bearer string) error {
	if err := keyring.Set(s.service, recBearer, bearer); err != nil {
		return fmt.Errorf("orgclient.SaveBearer: %w", err)
	}
	return nil
}

func (s *keychainStore) LoadBearer() (string, error) {
	v, err := keyring.Get(s.service, recBearer)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", ErrNoSecret
	}
	if err != nil {
		return "", fmt.Errorf("orgclient.LoadBearer: %w", err)
	}
	return v, nil
}

func (s *keychainStore) SaveAgentKey(key ed25519.PrivateKey) error {
	if err := keyring.Set(s.service, recAgentKey, base64.StdEncoding.EncodeToString(key)); err != nil {
		return fmt.Errorf("orgclient.SaveAgentKey: %w", err)
	}
	return nil
}

func (s *keychainStore) LoadAgentKey() (ed25519.PrivateKey, error) {
	v, err := keyring.Get(s.service, recAgentKey)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, ErrNoSecret
	}
	if err != nil {
		return nil, fmt.Errorf("orgclient.LoadAgentKey: %w", err)
	}
	return decodeAgentKey(v)
}

func (s *keychainStore) SaveVirtualKey(key string, generation uint64) error {
	v, err := encodeVirtualKey(key, generation)
	if err != nil {
		return err
	}
	if err := keyring.Set(s.service, recVirtualKey, v); err != nil {
		return fmt.Errorf("orgclient.SaveVirtualKey: %w", err)
	}
	return nil
}

func (s *keychainStore) LoadVirtualKey() (string, uint64, error) {
	v, err := keyring.Get(s.service, recVirtualKey)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", 0, ErrNoSecret
	}
	if err != nil {
		return "", 0, fmt.Errorf("orgclient.LoadVirtualKey: %w", err)
	}
	return decodeVirtualKey(v)
}

// SaveBreakGlassLeases implements BreakGlassLeaseStore (fourth slot). An empty
// payload removes the record.
func (s *keychainStore) SaveBreakGlassLeases(raw []byte) error {
	if len(raw) == 0 {
		if err := keyring.Delete(s.service, recBreakGlassLeases); err != nil && !errors.Is(err, keyring.ErrNotFound) {
			return fmt.Errorf("orgclient.SaveBreakGlassLeases: %w", err)
		}
		return nil
	}
	if err := keyring.Set(s.service, recBreakGlassLeases, string(raw)); err != nil {
		return fmt.Errorf("orgclient.SaveBreakGlassLeases: %w", err)
	}
	return nil
}

// LoadBreakGlassLeases implements BreakGlassLeaseStore.
func (s *keychainStore) LoadBreakGlassLeases() ([]byte, error) {
	v, err := keyring.Get(s.service, recBreakGlassLeases)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, ErrNoSecret
	}
	if err != nil {
		return nil, fmt.Errorf("orgclient.LoadBreakGlassLeases: %w", err)
	}
	return []byte(v), nil
}

func (s *keychainStore) Clear() error {
	var errs []error
	for _, rec := range []string{recBearer, recAgentKey, recVirtualKey, recBreakGlassLeases} {
		if err := keyring.Delete(s.service, rec); err != nil && !errors.Is(err, keyring.ErrNotFound) {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("orgclient.Clear: %w", errors.Join(errs...))
	}
	return nil
}

// --- 0600-file fallback store ----------------------------------------------

type fileStore struct {
	dir     string
	service string
}

func (s *fileStore) Backend() string { return "file" }

func (s *fileStore) path(rec string) string {
	return filepath.Join(s.dir, s.service+"."+rec)
}

func (s *fileStore) write(rec, val string) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("orgclient.fileStore: mkdir: %w", err)
	}
	if err := os.WriteFile(s.path(rec), []byte(val), 0o600); err != nil {
		return fmt.Errorf("orgclient.fileStore: write %s: %w", rec, err)
	}
	return nil
}

func (s *fileStore) read(rec string) (string, error) {
	b, err := os.ReadFile(s.path(rec))
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNoSecret
	}
	if err != nil {
		return "", fmt.Errorf("orgclient.fileStore: read %s: %w", rec, err)
	}
	return string(b), nil
}

func (s *fileStore) SaveBearer(bearer string) error { return s.write(recBearer, bearer) }
func (s *fileStore) LoadBearer() (string, error)    { return s.read(recBearer) }

func (s *fileStore) SaveAgentKey(key ed25519.PrivateKey) error {
	return s.write(recAgentKey, base64.StdEncoding.EncodeToString(key))
}

func (s *fileStore) LoadAgentKey() (ed25519.PrivateKey, error) {
	v, err := s.read(recAgentKey)
	if err != nil {
		return nil, err
	}
	return decodeAgentKey(v)
}

func (s *fileStore) SaveVirtualKey(key string, generation uint64) error {
	v, err := encodeVirtualKey(key, generation)
	if err != nil {
		return err
	}
	return s.write(recVirtualKey, v)
}

func (s *fileStore) LoadVirtualKey() (string, uint64, error) {
	v, err := s.read(recVirtualKey)
	if err != nil {
		return "", 0, err
	}
	return decodeVirtualKey(v)
}

// SaveBreakGlassLeases implements BreakGlassLeaseStore (0600 file slot).
func (s *fileStore) SaveBreakGlassLeases(raw []byte) error {
	if len(raw) == 0 {
		if err := os.Remove(s.path(recBreakGlassLeases)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("orgclient.SaveBreakGlassLeases: %w", err)
		}
		return nil
	}
	return s.write(recBreakGlassLeases, string(raw))
}

// LoadBreakGlassLeases implements BreakGlassLeaseStore.
func (s *fileStore) LoadBreakGlassLeases() ([]byte, error) {
	v, err := s.read(recBreakGlassLeases)
	if err != nil {
		return nil, err
	}
	return []byte(v), nil
}

func (s *fileStore) Clear() error {
	var errs []error
	for _, rec := range []string{recBearer, recAgentKey, recVirtualKey, recBreakGlassLeases} {
		if err := os.Remove(s.path(rec)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("orgclient.fileStore.Clear: %w", errors.Join(errs...))
	}
	return nil
}

// encodeVirtualKey and decodeVirtualKey are the shared JSON codec for the
// third BearerStore slot, used by both backends.
func encodeVirtualKey(key string, generation uint64) (string, error) {
	b, err := json.Marshal(virtualKeyRecord{Key: key, Generation: generation})
	if err != nil {
		return "", fmt.Errorf("orgclient: encode virtual key: %w", err)
	}
	return string(b), nil
}

func decodeVirtualKey(v string) (string, uint64, error) {
	var rec virtualKeyRecord
	if err := json.Unmarshal([]byte(v), &rec); err != nil {
		return "", 0, fmt.Errorf("orgclient: decode virtual key: %w", err)
	}
	return rec.Key, rec.Generation, nil
}

// decodeAgentKey validates a stored Ed25519 private key.
func decodeAgentKey(v string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("orgclient: decode agent key: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("orgclient: agent key wrong size: got %d want %d", len(raw), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(raw), nil
}
