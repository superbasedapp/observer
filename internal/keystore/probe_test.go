package keystore

import (
	"errors"
	"os/exec"
	"path/filepath"
	"runtime"
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
	defer func() { close(block); keychainProbeErr, probeTimeout = prevProbe, prevTimeout }()
	start := time.Now()
	o := OpenReport("svc-test", t.TempDir(), nil)
	if o.Reason != ReasonProbeTimeout || time.Since(start) > 5*time.Second {
		t.Fatalf("reason %q after %s", o.Reason, time.Since(start))
	}
}
