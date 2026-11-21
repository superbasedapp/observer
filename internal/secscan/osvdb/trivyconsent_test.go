package osvdb

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestTrivyConsentRecord: the Trivy accept is its own signed record (its
// own file, MAC domain and version): neither of the other accepts stands
// in for it, it stands in for neither, and the usual refusals hold.
func TestTrivyConsentRecord(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "security")
	key := testKey(7)
	if ReadTrivyConsent(dir, key).Accepted() {
		t.Fatal("no record reads accepted")
	}
	for name, rec := range map[string]func() error{
		"unknown surface": func() error { _, err := RecordTrivyConsent(dir, "agent", "u", time.Now(), key); return err },
		"no time":         func() error { _, err := RecordTrivyConsent(dir, "cli", "u", time.Time{}, key); return err },
		"no key":          func() error { _, err := RecordTrivyConsent(dir, "cli", "u", time.Now(), nil); return err },
	} {
		if rec() == nil {
			t.Errorf("%s: recorded", name)
		}
	}
	if _, err := RecordConsent(dir, "cli", "dev", time.Now(), key); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordOSConsent(dir, "cli", "dev", time.Now(), key); err != nil {
		t.Fatal(err)
	}
	if ReadTrivyConsent(dir, key).Accepted() {
		t.Fatal("the language or OS accept read as the Trivy accept")
	}
	for _, other := range []string{ConsentFile, OSConsentFile} {
		b, err := os.ReadFile(filepath.Join(dir, other))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, TrivyConsentFile), b, 0o600); err != nil {
			t.Fatal(err)
		}
		if ReadTrivyConsent(dir, key).Accepted() {
			t.Fatalf("%s copied under the Trivy name read accepted", other)
		}
	}
	at := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	c, err := RecordTrivyConsent(dir, "dashboard", "dev", at, key)
	if err != nil {
		t.Fatal(err)
	}
	got := ReadTrivyConsent(dir, key)
	if !got.Accepted() || !got.AcceptedAt.Equal(at) || got.Surface != "dashboard" || got.Version != TrivyConsentVersion || got != c {
		t.Fatalf("read back %+v, want %+v", got, c)
	}
	if ReadTrivyConsent(dir, testKey(6)).Accepted() {
		t.Fatal("a record read accepted under another key")
	}
	b, err := os.ReadFile(filepath.Join(dir, TrivyConsentFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, OSConsentFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if ReadOSConsent(dir, key).Accepted() {
		t.Fatal("the Trivy record copied under the OS name read accepted")
	}
	if !ReadConsent(dir, key).Accepted() {
		t.Fatal("the language accept was lost")
	}
}

// TestTrivyConsentText pins what the Trivy accept says: both hosts, the
// size to download and on disk, the 6-hour check, nothing about projects.
func TestTrivyConsentText(t *testing.T) {
	t.Parallel()
	for _, want := range []string{
		TrivyRegistryHost, TrivyBlobHost, "ghcr.io/aquasecurity/trivy-db:2", "about 140 MB to download",
		"about 1700 MB", "1.7 GB", "every 6 hours", "sends nothing about your projects or images",
		"Trivy itself never downloads anything", "show as not scanned",
	} {
		if !strings.Contains(TrivyConsentText, want) {
			t.Errorf("the Trivy accept text lacks %q:\n%s", want, TrivyConsentText)
		}
	}
	if strings.Contains(TrivyConsentText, FeedHost) {
		t.Error("the Trivy accept text names superbased.app, which does not serve Trivy's database")
	}
	if ConsentVersion != 2 || OSConsentVersion != 1 {
		t.Error("the Trivy accept must not bump the other accepts")
	}
}
