package keystore

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func withHomes(t *testing.T, env, acct string) {
	t.Helper()
	oe, oa := envObserverHome, accountObserverHome
	envObserverHome = func() string { return env }
	accountObserverHome = func() string { return acct }
	t.Cleanup(func() { envObserverHome, accountObserverHome = oe, oa })
}

// TestNamespaceKeepsHomesApart: the account's own Observer home keeps the
// unsuffixed service names (an existing install reads its entries as
// before), any other home gets its own short tag, and two homes never share
// one (Windows 11 Pro rerun 2026-10-25, D2: every isolated home's daemon
// wrote into the user's real Credential Manager).
func TestNamespaceKeepsHomesApart(t *testing.T) {
	acct := filepath.Join(t.TempDir(), "u", ".observer")
	a := filepath.Join(t.TempDir(), "iso-a", ".observer")
	b := filepath.Join(t.TempDir(), "iso-b", ".observer")
	for _, c := range []struct {
		name, env, acct string
		legacy          bool
	}{
		{name: "the account's own home", env: acct, acct: acct, legacy: true},
		{name: "an unresolvable account home", env: a, acct: "", legacy: true},
		{name: "an unresolvable process home", env: "", acct: acct, legacy: true},
		{name: "an isolated home", env: a, acct: acct},
	} {
		withHomes(t, c.env, c.acct)
		got := Namespace("sbo-change-record-v1")
		if c.legacy != (got == "sbo-change-record-v1") {
			t.Errorf("%s: Namespace = %q", c.name, got)
		}
		if !c.legacy && (!strings.HasPrefix(got, "sbo-change-record-v1.h") || len(HomeTag()) != 1+homeTagLen || !ValidName(got)) {
			t.Errorf("%s: Namespace = %q, tag %q", c.name, got, HomeTag())
		}
	}
	withHomes(t, a, acct)
	ta := HomeTag()
	withHomes(t, b, acct)
	if tb := HomeTag(); ta == tb {
		t.Fatalf("two homes share the tag %q", ta)
	}
}

// TestTestBinaryNeverReachesTheOSKeychain: in a test binary the keyring is
// the in-memory provider, so no test writes to the user's real store.
func TestTestBinaryNeverReachesTheOSKeychain(t *testing.T) {
	if OSKeyringActive() {
		t.Fatal("a test binary reaches the real OS keychain")
	}
}

// TestRemoveHomeEntriesRemovesOnlyThisHome: uninstall's removal clears every
// entry of the listed services in this home and none of another home's.
func TestRemoveHomeEntriesRemovesOnlyThisHome(t *testing.T) {
	acct := filepath.Join(t.TempDir(), "u", ".observer")
	a := filepath.Join(t.TempDir(), "iso-a", ".observer")
	b := filepath.Join(t.TempDir(), "iso-b", ".observer")
	withHomes(t, b, acct)
	if err := KeyringSet("sbo-test-svc-v1", "k", "other home"); err != nil {
		t.Fatal(err)
	}
	withHomes(t, a, acct)
	for _, rec := range []string{"k", "change-key-1"} {
		if err := KeyringSet("sbo-test-svc-v1", rec, "this home"); err != nil {
			t.Fatal(err)
		}
	}
	done, err := RemoveHomeEntries([]string{"sbo-test-svc-v1", "sbo-test-empty-v1"})
	if err != nil || len(done) != 2 {
		t.Fatalf("RemoveHomeEntries = %v, %v", done, err)
	}
	if _, err := KeyringGet("sbo-test-svc-v1", "change-key-1"); !errors.Is(err, ErrKeyringNotFound) {
		t.Fatalf("this home's entry survived: %v", err)
	}
	withHomes(t, b, acct)
	if v, err := KeyringGet("sbo-test-svc-v1", "k"); err != nil || v != "other home" {
		t.Fatalf("another home's entry was removed: %q %v", v, err)
	}
}
