package osvdb

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRemoteConsentRecords: the lookup consent and the private-names consent
// are each their own signed record: no other accept stands in for either,
// neither stands in for the other, a copied file under the other name reads
// not accepted, and a withdrawal reads not accepted at once.
func TestRemoteConsentRecords(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "security")
	key := testKey(9)
	if ReadRemoteConsent(dir, key).Accepted() || ReadRemotePrivateConsent(dir, key).Accepted() {
		t.Fatal("no record reads accepted")
	}
	for name, rec := range map[string]func() error{
		"unknown surface": func() error { _, err := RecordRemoteConsent(dir, "agent", "u", time.Now(), key); return err },
		"no time":         func() error { _, err := RecordRemoteConsent(dir, "cli", "u", time.Time{}, key); return err },
		"no key":          func() error { _, err := RecordRemotePrivateConsent(dir, "cli", "u", time.Now(), nil); return err },
	} {
		if rec() == nil {
			t.Errorf("%s: recorded", name)
		}
	}
	for _, rec := range []func() error{
		func() error { _, err := RecordConsent(dir, "cli", "dev", time.Now(), key); return err },
		func() error { _, err := RecordOSConsent(dir, "cli", "dev", time.Now(), key); return err },
		func() error { _, err := RecordTrivyConsent(dir, "cli", "dev", time.Now(), key); return err },
	} {
		if err := rec(); err != nil {
			t.Fatal(err)
		}
	}
	if ReadRemoteConsent(dir, key).Accepted() || ReadRemotePrivateConsent(dir, key).Accepted() {
		t.Fatal("another accept read as a lookup consent")
	}
	at := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	c, err := RecordRemoteConsent(dir, "dashboard", "dev", at, key)
	if err != nil {
		t.Fatal(err)
	}
	if got := ReadRemoteConsent(dir, key); !got.Accepted() || got != c || got.Version != RemoteConsentVersion {
		t.Fatalf("read back %+v, want %+v", got, c)
	}
	if ReadRemotePrivateConsent(dir, key).Accepted() {
		t.Fatal("the lookup consent read as the private-names consent")
	}
	b, err := os.ReadFile(filepath.Join(dir, RemoteConsentFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, RemotePrivateConsentFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if ReadRemotePrivateConsent(dir, key).Accepted() {
		t.Fatal("the lookup record copied under the private name read accepted")
	}
	if ReadRemoteConsent(dir, testKey(8)).Accepted() {
		t.Fatal("a record verified under another key")
	}
	if _, err := RecordRemotePrivateConsent(dir, "cli", "dev", at, key); err != nil {
		t.Fatal(err)
	}
	if !ReadRemotePrivateConsent(dir, key).Accepted() {
		t.Fatal("the private-names consent did not read back")
	}
	if err := WithdrawRemoteConsent(dir); err != nil {
		t.Fatal(err)
	}
	if err := WithdrawRemoteConsent(dir); err != nil {
		t.Fatalf("a second withdrawal: %v", err)
	}
	if ReadRemoteConsent(dir, key).Accepted() {
		t.Fatal("a withdrawn lookup consent reads accepted")
	}
	if err := WithdrawRemotePrivate(dir); err != nil || ReadRemotePrivateConsent(dir, key).Accepted() {
		t.Fatalf("private withdrawal: %v", err)
	}
	if !ReadConsent(dir, key).Accepted() {
		t.Fatal("a lookup withdrawal touched the database accept")
	}
}

// TestRemoteConsentTextNamesTheHosts: the text names both hosts the lookup
// reaches and says what is and is not sent.
func TestRemoteConsentTextNamesTheHosts(t *testing.T) {
	t.Parallel()
	for _, want := range []string{RemoteShardHost, FeedHost, "hash prefix", "never a package name or version", "never code", "IP address", "Private and internal"} {
		if !strings.Contains(RemoteConsentText, want) {
			t.Errorf("RemoteConsentText does not say %q", want)
		}
	}
	if RemoteShardHost != "shards.superbased.app" {
		t.Fatalf("RemoteShardHost = %q", RemoteShardHost)
	}
	if !strings.Contains(RemotePrivateConsentText, "dependency confusion") {
		t.Error("the private-names text does not name dependency confusion")
	}
}
