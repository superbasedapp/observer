package keystore

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"

	keyring "github.com/zalando/go-keyring"
)

// ErrNotFound is returned by Get (and Read) when nothing is stored under the
// name.
var ErrNotFound = errors.New("keystore: secret not present")

// ErrInsecureFallbackUnavailable is returned by every method of the store
// Open selects when the OS keychain is unavailable AND this platform build's
// file fallback is not verified secure (FileFallbackSecure() == false).
var ErrInsecureFallbackUnavailable = errors.New(
	"keystore: secure credential storage is unavailable on this platform build " +
		"(the OS keychain is unreachable and the plaintext file fallback has no " +
		"verified ACL/reparse-point protection on this platform); retry once the " +
		"OS keychain (e.g. Windows Credential Manager) is reachable",
)

// ErrInvalidName is returned when a secret name fails ValidName.
var ErrInvalidName = errors.New("keystore: invalid secret name")

// ErrValueTooLarge is returned when a value exceeds MaxValueBytes.
var ErrValueTooLarge = errors.New("keystore: secret value too large")

// MaxValueBytes caps one stored value (and one file read), so a hostile
// oversized file cannot be slurped unbounded.
const MaxValueBytes = 64 * 1024

// maxNameBytes caps a secret name.
const maxNameBytes = 200

// probeRecord is the throwaway record Open uses to test the keychain.
const probeRecord = "__sbo_keystore_probe__"

// Store persists named secrets outside the agent database.
type Store interface {
	// Get returns the secret stored under name, or ErrNotFound.
	Get(name string) (string, error)
	// Set stores value under name, replacing any previous value.
	Set(name, value string) error
	// Delete removes the secret stored under name. Absence is not an error.
	Delete(name string) error
	// Backend names the active backend ("keychain", "file", "memory" or
	// "unavailable") for diagnostics.
	Backend() string
	// SecurityDiagnostic returns a human-readable degraded-security warning,
	// or "" when the backend provides OS-backed protection.
	SecurityDiagnostic() string
}

// ValidName reports whether name may be used as a secret name: non-empty, at
// most 200 bytes, only ASCII letters, digits and . _ @ : -, and never "." or
// "..". The rule keeps a name safe as a file-name suffix (no separators, no
// traversal).
func ValidName(name string) bool {
	if name == "" || len(name) > maxNameBytes || name == "." || name == ".." {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '@', c == ':', c == '-':
		default:
			return false
		}
	}
	return true
}

func checkName(name string) error {
	if !ValidName(name) {
		return fmt.Errorf("%w: %q", ErrInvalidName, name)
	}
	return nil
}

// keychainProbe is the availability test Open runs. A package var so tests
// substitute it and never touch the real OS keychain.
var keychainProbe = KeychainUsable

// KeychainUsable probes the OS keychain with a full set/get/delete cycle of
// a throwaway record under service. It is the only reliable cross-platform
// availability test.
func KeychainUsable(service, probe string) bool {
	if err := keyring.Set(Namespace(service), probe, "1"); err != nil {
		return false
	}
	got, err := keyring.Get(Namespace(service), probe)
	_ = keyring.Delete(Namespace(service), probe)
	return err == nil && got == "1"
}

// Open selects a backend for the named-secret store of service: the OS
// keychain when a probe round-trip succeeds; otherwise the hardened 0600
// file store rooted at fallbackDir when FileFallbackSecure(); otherwise a
// fail-closed store. A nil logger is tolerated. Open performs no network
// I/O.
func Open(service, fallbackDir string, logger *slog.Logger) Store {
	if logger == nil {
		logger = slog.Default()
	}
	sentinel := filepath.Join(fallbackDir, ".keychain-unavailable")
	if keychainProbe(service, probeRecord) {
		_ = os.Remove(sentinel)
		return &keychainStore{service: service}
	}
	if !FileFallbackSecure() {
		logger.Warn("credentials: OS keychain unavailable and this platform build's file "+
			"fallback has no verified protection; failing closed", "service", service)
		return FailClosed()
	}
	if _, err := os.Stat(sentinel); err != nil {
		logger.Warn("credentials: OS keychain unavailable, falling back to hardened 0600 file store",
			"service", service, "dir", fallbackDir,
			"note", "secrets are stored without OS-backed encryption; this warning is suppressed on subsequent invocations")
		_ = os.MkdirAll(fallbackDir, 0o700)
		_ = os.WriteFile(sentinel, []byte("1"), 0o600)
	}
	return NewFileStore(service, fallbackDir)
}

// --- keychain --------------------------------------------------------------

type keychainStore struct {
	service string
}

func (s *keychainStore) Backend() string            { return "keychain" }
func (s *keychainStore) SecurityDiagnostic() string { return "" }

func (s *keychainStore) Get(name string) (string, error) {
	if err := checkName(name); err != nil {
		return "", err
	}
	v, err := keyring.Get(Namespace(s.service), name)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("keystore.Get: %w", err)
	}
	return v, nil
}

func (s *keychainStore) Set(name, value string) error {
	if err := checkName(name); err != nil {
		return err
	}
	if len(value) > MaxValueBytes {
		return ErrValueTooLarge
	}
	if err := keyring.Set(Namespace(s.service), name, value); err != nil {
		return fmt.Errorf("keystore.Set: %w", err)
	}
	return nil
}

func (s *keychainStore) Delete(name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	if err := keyring.Delete(Namespace(s.service), name); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("keystore.Delete: %w", err)
	}
	return nil
}

// --- file ------------------------------------------------------------------

// NewFileStore returns the hardened 0600 file store for service rooted at
// dir, bypassing the keychain probe. Open is the normal entry point; this
// exists for callers (and tests) that already decided on the file backend.
// It does not check FileFallbackSecure.
func NewFileStore(service, dir string) Store {
	return &fileStore{b: FileBackend{Dir: dir, Service: service}}
}

type fileStore struct {
	b FileBackend
}

func (s *fileStore) Backend() string { return "file" }

func (s *fileStore) SecurityDiagnostic() string {
	return "credentials are stored in 0600 files at " + s.b.Dir +
		" WITHOUT OS-backed encryption (the OS keychain was unavailable); " +
		"protection relies on filesystem permissions and ownership only"
}

func (s *fileStore) Get(name string) (string, error) {
	b, err := s.b.Read(name)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (s *fileStore) Set(name, value string) error { return s.b.Write(name, []byte(value)) }

func (s *fileStore) Delete(name string) error { return s.b.Remove(name) }

// --- fail closed -----------------------------------------------------------

// FailClosed returns the store Open selects when neither the keychain nor a
// verified file fallback is available: every Get/Set returns
// ErrInsecureFallbackUnavailable; Delete succeeds (nothing was stored).
func FailClosed() Store { return failClosedStore{} }

type failClosedStore struct{}

func (failClosedStore) Backend() string { return "unavailable" }

func (failClosedStore) SecurityDiagnostic() string {
	return "credential storage is disabled on this platform build: the OS " +
		"keychain is unreachable and the plaintext file fallback has no verified " +
		"ACL/reparse-point protection, so credentials are refused rather than " +
		"written insecurely (fail-closed)"
}

func (failClosedStore) Get(string) (string, error) { return "", ErrInsecureFallbackUnavailable }
func (failClosedStore) Set(string, string) error   { return ErrInsecureFallbackUnavailable }
func (failClosedStore) Delete(string) error        { return nil }

// --- memory ----------------------------------------------------------------

// MemStore is an in-memory Store for tests and development wiring only:
// nothing survives the process. The zero value is ready to use and safe for
// concurrent use.
type MemStore struct {
	mu sync.Mutex
	m  map[string]string
}

// Backend reports "memory".
func (s *MemStore) Backend() string { return "memory" }

// SecurityDiagnostic reports that nothing is persisted.
func (s *MemStore) SecurityDiagnostic() string {
	return "credentials are held in memory only and are lost when the process exits"
}

// Get returns the value stored under name, or ErrNotFound.
func (s *MemStore) Get(name string) (string, error) {
	if err := checkName(name); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[name]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

// Set stores value under name.
func (s *MemStore) Set(name, value string) error {
	if err := checkName(name); err != nil {
		return err
	}
	if len(value) > MaxValueBytes {
		return ErrValueTooLarge
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]string{}
	}
	s.m[name] = value
	return nil
}

// Delete removes name. Absence is not an error.
func (s *MemStore) Delete(name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, name)
	return nil
}

// Names returns the stored names in sorted order (a test helper).
func (s *MemStore) Names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.m))
	for k := range s.m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
