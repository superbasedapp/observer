package osvdb

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestOSConsentRecord: the OS accept is its own signed record (its own
// file, MAC domain and version): recording it never records the language
// accept, a language record never reads as the OS one, and the usual
// refusals hold (unknown surface, no time, no key, a forged or unsigned
// file).
func TestOSConsentRecord(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "security")
	key := testKey(9)
	if ReadOSConsent(dir, key).Accepted() {
		t.Fatal("no record reads accepted")
	}
	for name, rec := range map[string]func() error{
		"unknown surface": func() error { _, err := RecordOSConsent(dir, "agent", "u", time.Now(), key); return err },
		"no time":         func() error { _, err := RecordOSConsent(dir, "cli", "u", time.Time{}, key); return err },
		"no key":          func() error { _, err := RecordOSConsent(dir, "cli", "u", time.Now(), nil); return err },
	} {
		if rec() == nil {
			t.Errorf("%s: recorded", name)
		}
	}
	// The language accept does not stand in for the OS one.
	if _, err := RecordConsent(dir, "cli", "dev", time.Now(), key); err != nil {
		t.Fatal(err)
	}
	if ReadOSConsent(dir, key).Accepted() {
		t.Fatal("the language accept read as the OS accept")
	}
	// A language record copied under the OS name does not verify there
	// (the MAC domains differ).
	b, err := os.ReadFile(filepath.Join(dir, ConsentFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, OSConsentFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if ReadOSConsent(dir, key).Accepted() {
		t.Fatal("a language record under the OS name read accepted")
	}
	at := time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)
	c, err := RecordOSConsent(dir, "dashboard", "dev", at, key)
	if err != nil {
		t.Fatal(err)
	}
	got := ReadOSConsent(dir, key)
	if !got.Accepted() || !got.AcceptedAt.Equal(at) || got.Surface != "dashboard" || got.By != "dev" || got.Version != OSConsentVersion || got != c {
		t.Fatalf("read back %+v, want %+v", got, c)
	}
	if fi, err := os.Stat(filepath.Join(dir, OSConsentFile)); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0) {
		t.Fatalf("record mode %v %v", fi, err)
	}
	if ReadOSConsent(dir, testKey(8)).Accepted() {
		t.Fatal("a record read accepted under another key")
	}
	// Recording the OS accept left the language record as it was.
	if !ReadConsent(dir, key).Accepted() {
		t.Fatal("the language accept was lost")
	}
	for name, body := range map[string]string{
		"unsigned": `{"version":1,"accepted_at":"2026-11-04T09:00:00Z","surface":"cli"}`,
		"forged":   `{"version":1,"accepted_at":"2026-11-04T09:00:00Z","surface":"cli","mac":"AAAA"}`,
		"corrupt":  `{`,
	} {
		if err := os.WriteFile(filepath.Join(dir, OSConsentFile), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if ReadOSConsent(dir, key).Accepted() {
			t.Errorf("%s: read accepted", name)
		}
	}
}

// TestOSConsentText pins what the OS accept says: superbased.app only, no
// bucket, one accept for every release, on demand, the per-distribution
// sizes from the release table, and nothing about projects.
func TestOSConsentText(t *testing.T) {
	t.Parallel()
	for _, want := range []string{
		"superbased.app only", "there is no other source", "One accept covers every release",
		"Debian up to 62 MB", "Ubuntu up to 220 MB", "Alpine up to 7 MB", "Red Hat up to 4 MB", "Rocky Linux up to 3 MB",
		"sends nothing about your projects", "show as not scanned",
	} {
		if !strings.Contains(OSConsentText, want) {
			t.Errorf("the OS accept text lacks %q:\n%s", want, OSConsentText)
		}
	}
	if strings.Contains(OSConsentText, UpstreamHost) || strings.Contains(strings.ToLower(OSConsentText), "bucket") {
		t.Error("the OS accept text names the OSV bucket")
	}
	if ConsentVersion != 2 {
		t.Errorf("the language ConsentVersion moved to %d: the OS accept must not re-ask for the languages", ConsentVersion)
	}
}

// TestOSDistroSizes: one row per distribution, in table order, each its
// largest release's size.
func TestOSDistroSizes(t *testing.T) {
	t.Parallel()
	want := []OSDistroSize{{"Debian", 62}, {"Ubuntu", 220}, {"Alpine", 7}, {"Red Hat", 4}, {"Rocky Linux", 3}}
	got := OSDistroSizes()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d: got %v, want %v", i, got[i], want[i])
		}
	}
}
