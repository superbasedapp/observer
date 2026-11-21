package keystore

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
)

// TestChooseKeychain pins the choice table (KEYSTORE-LINUX-1): the OS
// keychain stays first off Linux whatever the environment says; on Linux an
// opt-in uses the keyring, an opt-out uses the file store, and otherwise the
// keyring is used only when it already holds this service's entries, which
// is only searched for when no explicit choice was made.
func TestChooseKeychain(t *testing.T) {
	for _, tc := range []struct {
		name          string
		keychainFirst bool
		env           string
		holds         bool
		want          bool
		wantSearched  bool
	}{
		{"windows or macOS", true, "", false, true, false},
		{"windows or macOS ignore an opt-out", true, "0", false, true, false},
		{"linux new install", false, "", false, false, true},
		{"linux keyring already holds entries", false, "", true, true, true},
		{"linux opt in", false, "1", false, true, false},
		{"linux opt in, words", false, " Yes ", false, true, false},
		{"linux opt out", false, "off", true, false, false},
		{"linux unknown value is ignored", false, "maybe", false, false, true},
	} {
		searched := false
		got := chooseKeychain(tc.keychainFirst, tc.env, func() bool { searched = true; return tc.holds })
		if got != tc.want || searched != tc.wantSearched {
			t.Errorf("%s: chosen=%v searched=%v, want chosen=%v searched=%v", tc.name, got, searched, tc.want, tc.wantSearched)
		}
	}
}

// TestKeychainChosenInATestBinary: the in-memory keyring is always chosen, so
// no test reaches the Secret Service search.
func TestKeychainChosenInATestBinary(t *testing.T) {
	if !KeychainChosen(testService) {
		t.Fatal("KeychainChosen = false in a test binary, want true (in-memory keyring)")
	}
}

// TestNotChosenIsNamedAndQuiet: where the keyring is not chosen the probe
// names the reason, and Open and OpenReport select the file store without
// the "OS keychain unavailable" WARN that a new Linux user saw at
// `observer connect` (L-142).
func TestNotChosenIsNamedAndQuiet(t *testing.T) {
	if got := FallbackReason(ErrKeychainNotChosen); got != ReasonKeychainNotChosen {
		t.Fatalf("FallbackReason = %q, want %q", got, ReasonKeychainNotChosen)
	}
	if !strings.Contains(FallbackDetail(ReasonKeychainNotChosen), EnvOSKeychain) {
		t.Fatalf("FallbackDetail does not name %s", EnvOSKeychain)
	}
	if !FileFallbackSecure() {
		t.Skip("the file store is never selected on this platform build")
	}
	prevChosen, prevProbe, prevProbeErr := keychainChosen, keychainProbe, keychainProbeErr
	keychainChosen = func(string) bool { return false }
	keychainProbe = func(string, string) bool { return false }
	keychainProbeErr = func(string, string) error { return ErrKeychainNotChosen }
	t.Cleanup(func() { keychainChosen, keychainProbe, keychainProbeErr = prevChosen, prevProbe, prevProbeErr })

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	if s := Open(testService, filepath.Join(t.TempDir(), "a"), logger); s.Backend() != "file" {
		t.Fatalf("Open backend = %q, want file", s.Backend())
	}
	o := OpenReport(testService+"-report", filepath.Join(t.TempDir(), "b"), logger)
	if o.Store.Backend() != "file" || o.Reason != ReasonKeychainNotChosen {
		t.Fatalf("OpenReport = %q / %q, want file / %q", o.Store.Backend(), o.Reason, ReasonKeychainNotChosen)
	}
	if logs.Len() != 0 {
		t.Fatalf("a chosen file store logged: %s", logs.String())
	}
}
