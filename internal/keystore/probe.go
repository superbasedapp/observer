package keystore

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	if !KeychainChosen(service) {
		return ErrKeychainNotChosen
	}
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

// ErrProbeInFlight is the probe's error when an earlier probe of the same
// service already timed out for its caller and is still blocked in the
// keychain. It wraps ErrProbeTimeout, so FallbackReason names it
// ReasonProbeTimeout: the keychain has still not answered.
var ErrProbeInFlight = fmt.Errorf("%w (an earlier probe of this service is still waiting for it)", ErrProbeTimeout)

// probeAbandonAfter is how long a probe that timed out may hold a service's
// guard. Past it the next probe starts afresh and the stuck goroutine no
// longer guards (it still ends on its own), so a keychain call that never
// returns holds the guard for at most this long, never until the process
// restarts (audit finding OC-A4). A variable for tests.
var probeAbandonAfter = 30 * time.Minute

// probeNow is the guard's clock (a variable for tests).
var probeNow = time.Now

// probeFlight is one running keychain probe of a service: callers that
// arrive while it runs share its outcome.
type probeFlight struct {
	done    chan struct{}
	err     error
	started time.Time
	// gaveUp: a caller's timeout passed before the probe answered, so the
	// keychain is not answering (set under probeFlights).
	gaveUp bool
}

// probeFlights holds the probe in flight per service and, per service, the
// count of probes that answered nil after a caller had given up on them
// (late successes; audit finding OC-A4). One probe per service runs at a
// time: a caller arriving while it runs waits for its outcome within its
// own timeout (single-flight), so a concurrent caller of a healthy
// keychain gets the keychain, not a timeout. Once a caller has given up on
// a probe, later callers neither wait nor start another until it returns
// or probeAbandonAfter passes, so a caller that retries can neither pile
// up blocked goroutines nor raise a new unlock prompt on every try (audit
// finding O2-W1).
var probeFlights = struct {
	sync.Mutex
	m    map[string]*probeFlight
	late map[string]uint64
}{m: map[string]*probeFlight{}, late: map[string]uint64{}}

// stuckLocked reports whether f is a probe a caller gave up on that still
// guards its service. probeFlights is held.
func (f *probeFlight) stuckLocked() bool {
	return f != nil && f.gaveUp && probeNow().Sub(f.started) < probeAbandonAfter
}

// ProbeInFlight reports whether a probe of service timed out for its
// caller and is still waiting for the keychain (and has not been
// abandoned): no new probe of it starts meanwhile.
func ProbeInFlight(service string) bool {
	probeFlights.Lock()
	defer probeFlights.Unlock()
	return probeFlights.m[service].stuckLocked()
}

// LateProbeSuccesses counts the probes of service that answered nil after
// a caller had given up on them: a caller that cached a timeout reason
// compares it with the count it saw then, and probes again at once when
// it grew (the keychain was unlocked meanwhile; audit finding OC-A4).
func LateProbeSuccesses(service string) uint64 {
	probeFlights.Lock()
	defer probeFlights.Unlock()
	return probeFlights.late[service]
}

// probeWithin runs the probe of service, waiting at most d for it: it
// joins a probe of the service already running, starts one otherwise, and
// returns ErrProbeInFlight at once when the running one was already given
// up on (a probe left blocked is never waited on again).
func probeWithin(service string, d time.Duration) error {
	probeFlights.Lock()
	f := probeFlights.m[service]
	switch {
	case f.stuckLocked():
		probeFlights.Unlock()
		return ErrProbeInFlight
	case f == nil || f.gaveUp:
		// None running, or one abandoned past probeAbandonAfter: start a
		// new one. The probe is read here, not in the goroutine: a probe
		// left running past the timeout must not read the package seam
		// after the caller has moved on (a test restores it; go test -race
		// found the read in the goroutine).
		f = &probeFlight{done: make(chan struct{}), started: probeNow()}
		probeFlights.m[service] = f
		probe := keychainProbeErr
		go func() {
			err := probe(service, probeRecord)
			probeFlights.Lock()
			f.err = err
			if f.gaveUp && err == nil {
				probeFlights.late[service]++
			}
			if probeFlights.m[service] == f {
				delete(probeFlights.m, service)
			}
			// Closed under the lock, so a caller whose timer fires sees
			// either the outcome or a probe it may give up on, never both.
			close(f.done)
			probeFlights.Unlock()
		}()
	}
	probeFlights.Unlock()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-f.done:
		return f.err
	case <-t.C:
	}
	probeFlights.Lock()
	select {
	case <-f.done:
		// It answered as the timer fired.
		probeFlights.Unlock()
		return f.err
	default:
	}
	f.gaveUp = true
	probeFlights.Unlock()
	return ErrProbeTimeout
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
	case errors.Is(err, ErrKeychainNotChosen):
		return ReasonKeychainNotChosen
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
	case ReasonKeychainNotChosen:
		return "this machine keeps credentials in the 0600 file store (set " + EnvOSKeychain + "=1 to use the OS keyring)"
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
	if reason == ReasonKeychainNotChosen || !keychainChosen(service) {
		// The file store is this machine's choice, not a fallback: no WARN.
		return Opened{Store: NewFileStore(service, fallbackDir), Reason: ReasonKeychainNotChosen}
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

// ProbeAbandonAfter is how long a probe that timed out may hold its
// service's guard before the next probe starts afresh.
func ProbeAbandonAfter() time.Duration { return probeAbandonAfter }
