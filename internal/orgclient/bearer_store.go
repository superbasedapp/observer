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

	"github.com/marmutapp/superbased-observer/internal/keystore"
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
// Warning hygiene (M4.4 of the 2026-06-02 teams test follow-ups, WINNODE2
// section 16c): the downgrade WARN prints once per install and state. The
// "already said" record is a notice marker under <fallbackDir>/notices
// (noticeFirst), never a file in the credential store: opening the store
// creates nothing under <fallbackDir>/org-bearer, so a read-only command
// (`observer org status`, `observer doctor`, an init dry run) leaves no
// credential-store marker behind. The marker is cleared
// on unenrol, so a later downgrade warns again.
func OpenBearerStore(service, fallbackDir string, logger *slog.Logger) BearerStore {
	return openBearerStore(service, fallbackDir, logger, true)
}

// OpenBearerStoreQuiet is OpenBearerStore without the downgrade warning and
// without recording its notice, for a caller on a node that is not enrolled
// (T-735, D-547): `observer proxy start` on a never-enrolled node warned
// about the org bearer keychain it would never use. The warning stays armed
// for the first enrolment, which opens the store with OpenBearerStore.
func OpenBearerStoreQuiet(service, fallbackDir string) BearerStore {
	return openBearerStore(service, fallbackDir, nil, false)
}

// legacyKeychainMarker is the file an older build wrote into the credential
// store directory on every downgrade. Nothing reads it any more; a Clear
// removes it.
const legacyKeychainMarker = ".keychain-unavailable"

// bearerNoticeKey names the downgrade warning's notice marker.
func bearerNoticeKey(service string) string { return "org-bearer-keychain-" + service }

func openBearerStore(service, fallbackDir string, logger *slog.Logger, warn bool) BearerStore {
	if logger == nil {
		logger = slog.Default()
	}
	storeDir := filepath.Join(fallbackDir, "org-bearer")
	if keychainUsable(service) {
		return &keychainStore{service: service, fallbackDir: fallbackDir}
	}
	if warn && noticeFirst(fallbackDir, bearerNoticeKey(service), "keychain unavailable") {
		logger.Warn(
			"org bearer: OS keychain unavailable, falling back to 0600 file store",
			"service", service, "dir", fallbackDir,
			"note", "this warning prints once per install; remove "+noticePath(fallbackDir, bearerNoticeKey(service))+" to see it again",
		)
	}
	return &fileStore{dir: storeDir, service: service, fallbackDir: fallbackDir}
}

// agentAccessKeyClearer is implemented by the two real BearerStore backends:
// it names the agent-access key store living under the SAME service and
// fallback directory, so Unenroll clears that key (keychain record AND 0600
// file) even when no AgentAccessKeyStore was injected (ledger AA-5).
type agentAccessKeyClearer interface {
	agentAccessKeys() AgentAccessKeyStore
}

// keychainUsable probes the keyring with a throwaway record. A full
// set/get/delete cycle is the only reliable cross-platform availability test
// (ErrUnsupportedPlatform alone misses headless Linux without a Secret
// Service). The probe record is always deleted.
func keychainUsable(service string) bool {
	if err := keystore.KeyringSet(service, recProbe, "1"); err != nil {
		return false
	}
	got, err := keystore.KeyringGet(service, recProbe)
	_ = keystore.KeyringDelete(service, recProbe)
	return err == nil && got == "1"
}

// --- keychain-backed store -------------------------------------------------

type keychainStore struct {
	service string
	// fallbackDir is the directory OpenBearerStore was given; it locates
	// the agent-access key's file fallback for Unenroll's clear.
	fallbackDir string
}

func (s *keychainStore) Backend() string { return "keychain" }

func (s *keychainStore) agentAccessKeys() AgentAccessKeyStore {
	return agentAccessKeyStoreForClear(s.service, s.fallbackDir, true)
}

// fileFallback is the 0600 file store openBearerStore returns for the same
// (service, fallbackDir) when the keychain is unavailable.
//
// Issue 1b (WINNODE merge follow-up): on Windows a process with no logon
// session (SSH key logon, WMI, session 0) cannot use Credential Manager, so
// an enrolment from there writes the bearer and agent key to this file store.
// A daemon started later from the developer's sign-in has a working keychain
// that holds neither; reading only the keychain made it report "not
// enrolled" and never push. LoadBearer and LoadAgentKey therefore fall back
// to this store on a keychain miss (the keychain wins when both hold one),
// and Clear clears it too.
//
// WINNODE2 merge ruling (audit H1): the credential is never moved. A file
// copy stays where the enrolment put it, because a process with no logon
// session (a session 0 or WMI daemon, an SSH CLI) can read only the file
// store; moving it into the keychain and deleting the files left those
// processes "not enrolled". To keep the two stores from diverging,
// SaveBearer and SaveAgentKey also overwrite a file copy that already
// exists (refreshFileCopy) and never create one.
func (s *keychainStore) fileFallback() *fileStore {
	return &fileStore{dir: filepath.Join(s.fallbackDir, "org-bearer"), service: s.service, fallbackDir: s.fallbackDir}
}

func (s *keychainStore) SaveBearer(bearer string) error {
	if err := keystore.KeyringSet(s.service, recBearer, bearer); err != nil {
		return fmt.Errorf("orgclient.SaveBearer: %w", err)
	}
	if err := s.refreshFileCopy(recBearer, bearer); err != nil {
		return fmt.Errorf("orgclient.SaveBearer: %w", err)
	}
	return nil
}

func (s *keychainStore) LoadBearer() (string, error) {
	v, err := keystore.KeyringGet(s.service, recBearer)
	if errors.Is(err, keystore.ErrKeyringNotFound) {
		return s.fileFallback().LoadBearer()
	}
	if err != nil {
		return "", fmt.Errorf("orgclient.LoadBearer: %w", err)
	}
	return v, nil
}

func (s *keychainStore) SaveAgentKey(key ed25519.PrivateKey) error {
	enc := base64.StdEncoding.EncodeToString(key)
	if err := keystore.KeyringSet(s.service, recAgentKey, enc); err != nil {
		return fmt.Errorf("orgclient.SaveAgentKey: %w", err)
	}
	if err := s.refreshFileCopy(recAgentKey, enc); err != nil {
		return fmt.Errorf("orgclient.SaveAgentKey: %w", err)
	}
	return nil
}

func (s *keychainStore) LoadAgentKey() (ed25519.PrivateKey, error) {
	v, err := keystore.KeyringGet(s.service, recAgentKey)
	if errors.Is(err, keystore.ErrKeyringNotFound) {
		return s.fileFallback().LoadAgentKey()
	}
	if err != nil {
		return nil, fmt.Errorf("orgclient.LoadAgentKey: %w", err)
	}
	return decodeAgentKey(v)
}

// refreshFileCopy overwrites the file store's copy of rec with val when one
// already exists, so a no-logon-session process reading the file store sees
// the same credential as the keychain (a desktop re-enrolment after an SSH
// one). It never creates a copy: a keychain enrolment writes nothing under
// org-bearer/. A copy that is not a regular file is refused, not followed.
func (s *keychainStore) refreshFileCopy(rec, val string) error {
	fs := s.fileFallback()
	fi, err := os.Lstat(fs.path(rec))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("check the file copy of %s: %w", rec, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("the file copy of %s is not a regular file; not overwritten", rec)
	}
	return fs.write(rec, val)
}

func (s *keychainStore) SaveVirtualKey(key string, generation uint64) error {
	v, err := encodeVirtualKey(key, generation)
	if err != nil {
		return err
	}
	if err := keystore.KeyringSet(s.service, recVirtualKey, v); err != nil {
		return fmt.Errorf("orgclient.SaveVirtualKey: %w", err)
	}
	return nil
}

func (s *keychainStore) LoadVirtualKey() (string, uint64, error) {
	v, err := keystore.KeyringGet(s.service, recVirtualKey)
	if errors.Is(err, keystore.ErrKeyringNotFound) {
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
		if err := keystore.KeyringDelete(s.service, recBreakGlassLeases); err != nil && !errors.Is(err, keystore.ErrKeyringNotFound) {
			return fmt.Errorf("orgclient.SaveBreakGlassLeases: %w", err)
		}
		return nil
	}
	if err := keystore.KeyringSet(s.service, recBreakGlassLeases, string(raw)); err != nil {
		return fmt.Errorf("orgclient.SaveBreakGlassLeases: %w", err)
	}
	return nil
}

// LoadBreakGlassLeases implements BreakGlassLeaseStore.
func (s *keychainStore) LoadBreakGlassLeases() ([]byte, error) {
	v, err := keystore.KeyringGet(s.service, recBreakGlassLeases)
	if errors.Is(err, keystore.ErrKeyringNotFound) {
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
		if err := keystore.KeyringDelete(s.service, rec); err != nil && !errors.Is(err, keystore.ErrKeyringNotFound) {
			errs = append(errs, err)
		}
	}
	// The file store LoadBearer falls back to: an unenrolled node must not
	// read a stale file bearer back as enrolled.
	if err := s.fileFallback().Clear(); err != nil {
		errs = append(errs, err)
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
	// fallbackDir is the directory OpenBearerStore was given (dir's parent).
	fallbackDir string
}

func (s *fileStore) Backend() string { return "file" }

func (s *fileStore) agentAccessKeys() AgentAccessKeyStore {
	return agentAccessKeyStoreForClear(s.service, s.fallbackDir, false)
}

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
	_ = os.Remove(filepath.Join(s.dir, legacyKeychainMarker))
	noticeReset(s.fallbackDir, bearerNoticeKey(s.service))
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
