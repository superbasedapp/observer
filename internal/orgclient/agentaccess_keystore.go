package orgclient

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	keyring "github.com/zalando/go-keyring"
)

// Agent Access key custody (operator ruling 2026-09-27, superseding the
// keychain-only reading of R8.13): the per-device agent-access private key
// lives in the OS keychain FIRST and, when the keychain cannot round-trip a
// record (headless Linux: servers, SSH dev boxes, CI, cloud VMs), in a
// hardened 0600 file next to the enrolment bearer's own file fallback - the
// same posture OpenBearerStore already gives the enrolment bearer. Default on,
// no configuration. The file is
//
//	<fallbackDir>/org-bearer/<service>.agent-access-key
//
// (fallbackDir = the directory of the observer DB, as for the bearer; the
// record name follows the bearer fileStore's "<service>.<record>" convention)
// holding the SAME envelope as the keychain value
// ("sbo-aak-v1:<alg>:<base64 PKCS#8>"), written and read through the hardened
// helpers in agentaccess_keyfile.go.
//
// Backend selection at open (walked top-down, first match wins):
//
//  1. keychain usable AND it holds the key            -> keychain
//  2. keychain usable AND only the file holds the key -> file (see below)
//  3. keychain usable, no key anywhere                -> keychain (new keys go there)
//  4. keychain unusable, file fallback usable         -> file (WARN once)
//  5. keychain unusable, file fallback unusable       -> ErrAgentAccessKeychainUnavailable
//
// Row 2 is deliberate: a key first generated into the file on a host whose
// keychain later comes up (someone starts a Secret Service) keeps being used
// from the file. Migrating it would be invisible and generating a new one
// would silently rotate the device key, which the org server only learns
// through a fresh registration (a new agent_credential, possibly against the
// member's device cap). The file therefore stays authoritative until an
// unenrol / ClearAgentAccessKey removes it. When BOTH hold a key (only after a
// transient keychain outage at one start), row 1 wins; the stale file is left
// for ClearAgentAccessKey, which always removes both.

// agentAccessFallbackSentinel suppresses the fallback WARN on later
// invocations (the bearer store's ".keychain-unavailable" pattern, under its
// own name so the bearer's sentinel does not silence this one).
const agentAccessFallbackSentinel = ".agent-access-key-file-fallback"

// agentAccessKeyStore is the one AgentAccessKeyStore implementation.
type agentAccessKeyStore struct {
	service string
	// path is the file-fallback location; "" when no file fallback exists
	// on this host (non-unix build, or no fallback directory).
	path string
	// useFile selects the backend: the file at path, else the keychain.
	useFile bool
	// keychain reports the keychain round-tripped at open: ClearAgentAccessKey
	// reports keychain delete errors only then (an unusable keychain holds
	// nothing we could delete).
	keychain bool
}

// agentAccessKeyFilePath returns the file-fallback path for (service,
// fallbackDir), or "" when this build or host has no file fallback.
func agentAccessKeyFilePath(service, fallbackDir string) string {
	if !agentAccessKeyFileSupported || fallbackDir == "" {
		return ""
	}
	return filepath.Join(fallbackDir, "org-bearer", service+"."+recAgentAccessKey)
}

// OpenAgentAccessKeyStore is OpenAgentAccessKeyStoreIn with the default
// fallback directory (~/.observer, the default observer DB directory) and
// slog.Default.
func OpenAgentAccessKeyStore(service string) (AgentAccessKeyStore, error) {
	dir := ""
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dir = filepath.Join(home, ".observer")
	}
	return OpenAgentAccessKeyStoreIn(service, dir, nil)
}

// OpenAgentAccessKeyStoreIn returns the agent-access key store for service
// (the org client's KeychainID): the OS keychain when it round-trips a
// record, else the hardened 0600 file under fallbackDir (the same directory
// OpenBearerStore is given). See the selection table above. It fails closed
// with ErrAgentAccessKeychainUnavailable only when NEITHER backend is usable.
// A nil logger is tolerated (slog.Default is used).
func OpenAgentAccessKeyStoreIn(service, fallbackDir string, logger *slog.Logger) (AgentAccessKeyStore, error) {
	if logger == nil {
		logger = slog.Default()
	}
	st := &agentAccessKeyStore{service: service, path: agentAccessKeyFilePath(service, fallbackDir)}
	var sentinel string
	if st.path != "" {
		sentinel = filepath.Join(filepath.Dir(st.path), agentAccessFallbackSentinel)
	}
	if keychainUsable(service) {
		st.keychain = true
		if _, err := keyring.Get(service, recAgentAccessKey); errors.Is(err, keyring.ErrNotFound) && st.path != "" {
			if _, statErr := os.Lstat(st.path); statErr == nil {
				st.useFile = true // row 2: never silently rotate a file-held key
			}
		}
		if !st.useFile && sentinel != "" {
			// Keychain in use again: re-arm the WARN for a future downgrade.
			_ = os.Remove(sentinel)
		}
		return st, nil
	}
	if st.path == "" {
		return nil, ErrAgentAccessKeychainUnavailable
	}
	if err := ensureAgentAccessKeyDir(filepath.Dir(st.path)); err != nil {
		return nil, fmt.Errorf("%w: file fallback: %w", ErrAgentAccessKeychainUnavailable, err)
	}
	st.useFile = true
	if _, err := os.Stat(sentinel); err != nil {
		logger.Warn(
			"agent-access key: OS keychain unavailable, falling back to 0600 file store",
			"service", service, "path", st.path,
			"note", "this warning is suppressed on subsequent invocations; remove "+sentinel+" to re-arm",
		)
		_ = os.WriteFile(sentinel, []byte("1"), 0o600)
	}
	return st, nil
}

// agentAccessKeyStoreForClear is the store an unenrol clears: both backends'
// locations for (service, fallbackDir), whatever the active one is.
func agentAccessKeyStoreForClear(service, fallbackDir string, keychain bool) *agentAccessKeyStore {
	return &agentAccessKeyStore{service: service, path: agentAccessKeyFilePath(service, fallbackDir), keychain: keychain}
}

// LoadAgentAccessKey implements AgentAccessKeyStore.
func (s *agentAccessKeyStore) LoadAgentAccessKey() (AgentAccessKey, error) {
	if s.useFile {
		b, err := readAgentAccessKeyFile(s.path)
		if errors.Is(err, ErrNoSecret) {
			return AgentAccessKey{}, ErrNoSecret
		}
		if err != nil {
			return AgentAccessKey{}, fmt.Errorf("orgclient.LoadAgentAccessKey: %w", err)
		}
		return decodeAgentAccessKey(string(b))
	}
	v, err := keyring.Get(s.service, recAgentAccessKey)
	if errors.Is(err, keyring.ErrNotFound) {
		return AgentAccessKey{}, ErrNoSecret
	}
	if err != nil {
		return AgentAccessKey{}, fmt.Errorf("orgclient.LoadAgentAccessKey: %w", err)
	}
	return decodeAgentAccessKey(v)
}

// SaveAgentAccessKey implements AgentAccessKeyStore.
func (s *agentAccessKeyStore) SaveAgentAccessKey(k AgentAccessKey) error {
	v, err := encodeAgentAccessKey(k)
	if err != nil {
		return err
	}
	if s.useFile {
		if err := writeAgentAccessKeyFile(s.path, []byte(v)); err != nil {
			return fmt.Errorf("orgclient.SaveAgentAccessKey: %w", err)
		}
		return nil
	}
	if err := keyring.Set(s.service, recAgentAccessKey, v); err != nil {
		return fmt.Errorf("orgclient.SaveAgentAccessKey: %w", err)
	}
	return nil
}

// ClearAgentAccessKey implements AgentAccessKeyStore: it removes the key from
// BOTH the keychain and the file fallback, whichever is active. Absence is not
// an error.
func (s *agentAccessKeyStore) ClearAgentAccessKey() error {
	var errs []error
	if s.path != "" {
		if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if err := keyring.Delete(s.service, recAgentAccessKey); err != nil && !errors.Is(err, keyring.ErrNotFound) && s.keychain {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("orgclient.ClearAgentAccessKey: %w", errors.Join(errs...))
	}
	return nil
}

// location names the active backend ("keychain" or "file <path>").
func (s *agentAccessKeyStore) location() string {
	if s.useFile {
		return "file " + s.path
	}
	return "keychain"
}

// AgentAccessKeyLocation names where keys holds the agent-access key -
// "keychain" or "file <path>" - for diagnostics (`observer mcp doctor`); ""
// for a store this package did not open (a test fake).
func AgentAccessKeyLocation(keys AgentAccessKeyStore) string {
	if s, ok := keys.(*agentAccessKeyStore); ok && s != nil {
		return s.location()
	}
	return ""
}
