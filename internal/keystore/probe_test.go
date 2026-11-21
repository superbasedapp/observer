package keystore

import (
	"errors"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// macOSLockedErrors are the error values the macOS live run saw over a
// non-interactive session (live-macos-report check 6): /usr/bin/security
// exits 36 with "User interaction is not allowed.".
func macOSLockedErrors(t *testing.T) []error {
	t.Helper()
	out := []error{errors.New("SecKeychainItemCreateFromContent (<default>): User interaction is not allowed.")}
	if runtime.GOOS != "windows" {
		if _, err := exec.LookPath("sh"); err == nil {
			err := exec.Command("sh", "-c", "exit 36").Run()
			var ee *exec.ExitError
			if !errors.As(err, &ee) || ee.ExitCode() != 36 {
				t.Fatalf("could not make an exit-36 error: %v", err)
			}
			out = append(out, err)
		}
	}
	return out
}

func TestFallbackReason(t *testing.T) {
	for _, err := range macOSLockedErrors(t) {
		if got := FallbackReason(err); got != ReasonInteractionNotAllowed {
			t.Errorf("%v: %q", err, got)
		}
	}
	if FallbackReason(nil) != "" || FallbackReason(ErrProbeTimeout) != ReasonProbeTimeout || FallbackReason(errors.New("dbus: no secret service")) != ReasonKeychainUnavailable {
		t.Fatal("reason table")
	}
	if FallbackDetail(ReasonInteractionNotAllowed) == FallbackDetail(ReasonKeychainUnavailable) {
		t.Fatal("the locked keychain needs its own words")
	}
}

// TestOpenReportLockedKeychain: the locked-keychain error routes to the
// 0600 file fallback (fail-closed where the file store is not verified)
// with the named reason, and the same secret is read back by a second open
// (no new secret per call).
func TestOpenReportLockedKeychain(t *testing.T) {
	for _, locked := range macOSLockedErrors(t) {
		prev := keychainProbeErr
		keychainProbeErr = func(string, string) error { return locked }
		dir := filepath.Join(t.TempDir(), "keys")
		o := OpenReport("svc-test", dir, nil)
		keychainProbeErr = prev
		if o.Reason != ReasonInteractionNotAllowed {
			t.Fatalf("%v: reason %q", locked, o.Reason)
		}
		if !FileFallbackSecure() {
			if o.Store.Backend() != "unavailable" {
				t.Fatalf("backend %s", o.Store.Backend())
			}
			continue
		}
		if o.Store.Backend() != "file" {
			t.Fatalf("backend %s", o.Store.Backend())
		}
		if err := o.Store.Set("k", "v"); err != nil {
			t.Fatal(err)
		}
		keychainProbeErr = func(string, string) error { return locked }
		again := OpenReport("svc-test", dir, nil)
		keychainProbeErr = prev
		if v, err := again.Store.Get("k"); err != nil || v != "v" {
			t.Fatalf("second open: %q %v", v, err)
		}
	}
}

// TestOpenReportProbeTimeout: a keychain that never answers is a named
// reason after the timeout, never a hang.
func TestOpenReportProbeTimeout(t *testing.T) {
	prevProbe, prevTimeout := keychainProbeErr, probeTimeout
	block := make(chan struct{})
	keychainProbeErr = func(string, string) error { <-block; return nil }
	probeTimeout = 50 * time.Millisecond
	defer func() {
		close(block)
		for ProbeInFlight("svc-test") {
			time.Sleep(time.Millisecond)
		}
		keychainProbeErr, probeTimeout = prevProbe, prevTimeout
	}()
	start := time.Now()
	o := OpenReport("svc-test", t.TempDir(), nil)
	if o.Reason != ReasonProbeTimeout || time.Since(start) > 5*time.Second {
		t.Fatalf("reason %q after %s", o.Reason, time.Since(start))
	}
}

// TestProbeInFlight (audit finding O2-W1): while a timed-out probe of a
// service is still blocked in the keychain, a second open starts no new
// probe and answers the timeout reason at once; another service is not
// held up; once the blocked call returns, the next open probes again.
func TestProbeInFlight(t *testing.T) {
	prevProbe, prevTimeout := keychainProbeErr, probeTimeout
	block := make(chan struct{})
	var mu sync.Mutex
	calls := map[string]int{}
	keychainProbeErr = func(service, _ string) error {
		mu.Lock()
		calls[service]++
		mu.Unlock()
		if service == "svc-blocked" {
			<-block
		}
		return nil
	}
	probeTimeout = 30 * time.Millisecond
	defer func() { keychainProbeErr, probeTimeout = prevProbe, prevTimeout }()
	count := func(s string) int { mu.Lock(); defer mu.Unlock(); return calls[s] }

	if o := OpenReport("svc-blocked", t.TempDir(), nil); o.Reason != ReasonProbeTimeout {
		t.Fatalf("first open: %q", o.Reason)
	}
	if !ProbeInFlight("svc-blocked") {
		t.Fatal("the blocked probe is not counted")
	}
	start := time.Now()
	if o := OpenReport("svc-blocked", t.TempDir(), nil); o.Reason != ReasonProbeTimeout || time.Since(start) > 20*time.Millisecond {
		t.Fatalf("second open: %q after %s", o.Reason, time.Since(start))
	}
	if n := count("svc-blocked"); n != 1 {
		t.Fatalf("%d probes started while one was blocked", n)
	}
	if !errors.Is(probeWithin("svc-blocked", time.Second), ErrProbeInFlight) || !errors.Is(ErrProbeInFlight, ErrProbeTimeout) {
		t.Fatal("ErrProbeInFlight")
	}
	if o := OpenReport("svc-free", t.TempDir(), nil); o.Reason != "" {
		t.Fatalf("another service held up: %q", o.Reason)
	}
	close(block)
	deadline := time.Now().Add(5 * time.Second)
	for ProbeInFlight("svc-blocked") {
		if time.Now().After(deadline) {
			t.Fatal("the probe never cleared")
		}
		time.Sleep(time.Millisecond)
	}
	if o := OpenReport("svc-blocked", t.TempDir(), nil); o.Reason != "" || count("svc-blocked") != 2 {
		t.Fatalf("after the call returned: %q, %d probes", o.Reason, count("svc-blocked"))
	}
}

// TestProbeSingleFlight is audit finding OC-A4: two opens of one service
// that overlap while the keychain answers in 50 ms both get the keychain
// (the second waits for the first probe's outcome, no second probe runs);
// a probe given up on that later answers nil is counted as a late success;
// one stuck past probeAbandonAfter no longer guards the service.
func TestProbeSingleFlight(t *testing.T) {
	prevProbe, prevTimeout, prevNow := keychainProbeErr, probeTimeout, probeNow
	var mu sync.Mutex
	calls := 0
	release := make(chan struct{})
	keychainProbeErr = func(service, _ string) error {
		mu.Lock()
		calls++
		mu.Unlock()
		if service == "svc-slow" {
			<-release
			return nil
		}
		time.Sleep(50 * time.Millisecond)
		return nil
	}
	probeTimeout = 5 * time.Second
	now := time.Unix(1793000000, 0)
	var nowMu sync.Mutex
	probeNow = func() time.Time { nowMu.Lock(); defer nowMu.Unlock(); return now }
	defer func() {
		for ProbeInFlight("svc-slow") || ProbeInFlight("svc-single") {
			time.Sleep(time.Millisecond)
		}
		keychainProbeErr, probeTimeout, probeNow = prevProbe, prevTimeout, prevNow
	}()

	dir := t.TempDir()
	var wg sync.WaitGroup
	reasons := make([]string, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i == 1 {
				time.Sleep(10 * time.Millisecond)
			}
			reasons[i] = OpenReport("svc-single", dir, nil).Reason
		}(i)
	}
	wg.Wait()
	mu.Lock()
	n := calls
	mu.Unlock()
	if reasons[0] != "" || reasons[1] != "" || n != 1 {
		t.Fatalf("overlapping opens of a healthy keychain: reasons %q, %d probes", reasons, n)
	}

	if err := probeWithin("svc-slow", 20*time.Millisecond); !errors.Is(err, ErrProbeTimeout) || errors.Is(err, ErrProbeInFlight) {
		t.Fatalf("first slow probe: %v", err)
	}
	if err := probeWithin("svc-slow", time.Second); !errors.Is(err, ErrProbeInFlight) {
		t.Fatalf("a probe given up on still guards: %v", err)
	}
	nowMu.Lock()
	now = now.Add(probeAbandonAfter + time.Second)
	nowMu.Unlock()
	if ProbeInFlight("svc-slow") {
		t.Fatal("a probe stuck past probeAbandonAfter still guards")
	}
	before := LateProbeSuccesses("svc-slow")
	go func() { time.Sleep(20 * time.Millisecond); close(release) }()
	if err := probeWithin("svc-slow", 5*time.Second); err != nil {
		t.Fatalf("the probe after the abandonment: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for LateProbeSuccesses("svc-slow") == before {
		if time.Now().After(deadline) {
			t.Fatal("the late success of the abandoned probe was not counted")
		}
		time.Sleep(time.Millisecond)
	}
}
