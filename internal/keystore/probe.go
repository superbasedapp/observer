package keystore

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	keyring "github.com/zalando/go-keyring"
)

// probe.go is OpenReport: Open with the reason the OS keychain was not used
// (security plan 7.10 key storage; the macOS live run's check 6). Over a
// non-interactive session (ssh, a launchd background job) the macOS login
// keychain is locked, and /usr/bin/security answers "User interaction is
// not allowed." (errSecInteractionNotAllowed, exit status 36). That error
// must route to the hardened 0600 file fallback with a named reason the
// caller can show, never hang and never fail silently.

// The fallback reasons OpenReport names ("" when the keychain is in use).
const (
	// ReasonInteractionNotAllowed: the macOS keychain is locked and this
	// session cannot unlock it (errSecInteractionNotAllowed, exit status 36).
	ReasonInteractionNotAllowed = "keychain_interaction_not_allowed"
	// ReasonProbeTimeout: the keychain did not answer within ProbeTimeout.
	ReasonProbeTimeout = "keychain_probe_timeout"
	// ReasonKeychainUnavailable: any other keychain failure (no Secret
	// Service on a headless Linux, no Credential Manager access).
	ReasonKeychainUnavailable = "keychain_unavailable"
)

// ErrProbeTimeout is the probe's error when the keychain did not answer in
// time.
var ErrProbeTimeout = errors.New("keystore: the OS keychain did not answer the probe in time")

// probeTimeout bounds the keychain probe (a var so tests can shorten it).
var probeTimeout = 10 * time.Second

// keychainProbeErr is the probe OpenReport runs (a var so tests substitute
// it and never touch the real keychain).
var keychainProbeErr = KeychainProbe

// KeychainProbe is KeychainUsable with the error: a full set/get/delete
// cycle of a throwaway record under service.
func KeychainProbe(service, probe string) error {
	if err := keyring.Set(Namespace(service), probe, "1"); err != nil {
		return err
	}
	got, err := keyring.Get(Namespace(service), probe)
	_ = keyring.Delete(Namespace(service), probe)
	if err != nil {
		return err
	}
	if got != "1" {
		return errors.New("keystore: the keychain probe read back another value")
	}
	return nil
}

// probeWithin runs the probe, giving up after d (the probe goroutine is left
// to finish on its own; nothing waits on it).
func probeWithin(service string, d time.Duration) error {
	done := make(chan error, 1)
	// The probe is read here, not in the goroutine: a probe left running past
	// the timeout must not read the package seam after the caller has moved
	// on (a test restores it; go test -race found the read in the goroutine).
	probe := keychainProbeErr
	go func() { done <- probe(service, probeRecord) }()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case err := <-done:
		return err
	case <-t.C:
		return ErrProbeTimeout
	}
}

// IsInteractionNotAllowed reports the macOS locked-keychain error: the
// keychain tool's exit status 36, or its "User interaction is not allowed"
// text (errSecInteractionNotAllowed, -25308).
func IsInteractionNotAllowed(err error) bool {
	if err == nil {
		return false
	}
	var exit interface{ ExitCode() int }
	if errors.As(err, &exit) && exit.ExitCode() == 36 {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "User interaction is not allowed") || strings.Contains(s, "exit status 36") || strings.Contains(s, "-25308")
}

// FallbackReason names a keychain failure ("" for nil).
func FallbackReason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrProbeTimeout):
		return ReasonProbeTimeout
	case IsInteractionNotAllowed(err):
		return ReasonInteractionNotAllowed
	}
	return ReasonKeychainUnavailable
}

// FallbackDetail is a reason in plain words.
func FallbackDetail(reason string) string {
	switch reason {
	case "":
		return "the OS keychain is in use"
	case ReasonInteractionNotAllowed:
		return "the macOS login keychain is locked in this non-interactive session (errSecInteractionNotAllowed)"
	case ReasonProbeTimeout:
		return "the OS keychain did not answer in time"
	}
	return "the OS keychain is not reachable"
}

// Opened is what OpenReport selected.
type Opened struct {
	Store Store
	// Reason is "" when the OS keychain is in use; otherwise why it was not
	// (the 0600 file fallback, or the fail-closed store, was selected).
	Reason string
}

// OpenReport is Open with the reason: the OS keychain when its probe
// round-trips within ProbeTimeout, otherwise the hardened 0600 file store
// at fallbackDir (FileFallbackSecure) or the fail-closed store, with the
// named reason. It never waits on the keychain longer than the timeout.
func OpenReport(service, fallbackDir string, logger *slog.Logger) Opened {
	if logger == nil {
		logger = slog.Default()
	}
	sentinel := filepath.Join(fallbackDir, ".keychain-unavailable")
	err := probeWithin(service, probeTimeout)
	if err == nil {
		_ = os.Remove(sentinel)
		return Opened{Store: &keychainStore{service: service}}
	}
	reason := FallbackReason(err)
	if !FileFallbackSecure() {
		logger.Warn("credentials: OS keychain unavailable and this platform build's file "+
			"fallback has no verified protection; failing closed", "service", service, "reason", reason)
		return Opened{Store: FailClosed(), Reason: reason}
	}
	if _, serr := os.Stat(sentinel); serr != nil {
		logger.Warn("credentials: OS keychain unavailable, falling back to hardened 0600 file store",
			"service", service, "dir", fallbackDir, "reason", reason,
			"note", "secrets are stored without OS-backed encryption; this warning is suppressed on subsequent invocations")
		_ = os.MkdirAll(fallbackDir, 0o700)
		_ = os.WriteFile(sentinel, []byte("1"), 0o600)
	}
	return Opened{Store: NewFileStore(service, fallbackDir), Reason: reason}
}

// NewKeychainStore returns the OS keychain store for service without a
// probe: for reading or deleting a secret a caller knows is in the
// keychain. A locked or absent keychain answers its own error.
func NewKeychainStore(service string) Store { return &keychainStore{service: service} }
