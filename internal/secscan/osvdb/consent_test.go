package osvdb

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testKey is a posture key for the tests.
func testKey(b byte) []byte {
	k := make([]byte, 32)
	k[0] = b
	return k
}

// TestConsentRecord: no record, a record from an unknown surface, an older
// version or a corrupt file all read not accepted; a recorded accept
// reads back with its time, surface and account, 0600.
func TestConsentRecord(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "security")
	key := testKey(7)
	if ReadConsent(dir, key).Accepted() {
		t.Fatal("no record reads accepted")
	}
	if _, err := RecordConsent(dir, "terminal", "u", time.Now(), key); err == nil {
		t.Fatal("a terminal start recorded the accept")
	}
	if _, err := RecordConsent(dir, "cli", "u", time.Time{}, key); err == nil {
		t.Fatal("an accept with no time was recorded")
	}
	if _, err := RecordConsent(dir, "cli", "u", time.Now(), nil); err == nil {
		t.Fatal("an accept with no signing key was recorded")
	}
	at := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	c, err := RecordConsent(dir, "cli", "dev", at, key)
	if err != nil {
		t.Fatal(err)
	}
	got := ReadConsent(dir, key)
	if !got.Accepted() || !got.AcceptedAt.Equal(at) || got.Surface != "cli" || got.By != "dev" || got != c {
		t.Fatalf("read back %+v, want %+v", got, c)
	}
	if fi, err := os.Stat(filepath.Join(dir, ConsentFile)); err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("record mode %v %v", fi, err)
	}
	for name, body := range map[string]string{
		"older version":        `{"version":0,"accepted_at":"2026-10-21T09:00:00Z","surface":"cli"}`,
		"unknown surface":      `{"version":1,"accepted_at":"2026-10-21T09:00:00Z","surface":"agent"}`,
		"no time":              `{"version":1,"surface":"dashboard"}`,
		"corrupt":              `{`,
		"too large":            `{"by":"` + strings.Repeat("x", 5000) + `"}`,
		"verified in the file": `{"version":1,"accepted_at":"2026-10-21T09:00:00Z","surface":"cli","Verified":true}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, ConsentFile), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if ReadConsent(dir, key).Accepted() {
			t.Errorf("%s reads accepted", name)
		}
	}
	if !strings.Contains(ConsentText, Source) || !strings.Contains(ConsentText, "300 MB") {
		t.Errorf("the accept text does not name the size and source: %s", ConsentText)
	}
}

// TestConsentRecordIsSigned is lane sec-deps4 audit finding 1: a record an
// agent wrote by hand (the shape an older plan-branch build wrote, with no
// MAC), one with a forged or copied MAC, one whose fields were changed
// after signing, or one read under another key never reads accepted; only
// the accept path's own signed record does.
func TestConsentRecordIsSigned(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "security")
	key := testKey(9)
	at := time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)
	signed, err := RecordConsent(dir, "dashboard", "dev", at, key)
	if err != nil {
		t.Fatal(err)
	}
	if !ReadConsent(dir, key).Accepted() {
		t.Fatal("the signed record does not read accepted")
	}
	if ReadConsent(dir, testKey(10)).Accepted() {
		t.Fatal("the record reads accepted under another key")
	}
	if ReadConsent(dir, nil).Accepted() {
		t.Fatal("the record reads accepted with no key")
	}
	for name, body := range map[string]string{
		"hand-written, no MAC (an older build's shape)": `{"version":1,"accepted_at":"2026-10-21T09:00:00Z","surface":"cli"}`,
		"forged MAC":            `{"version":1,"accepted_at":"2026-10-21T09:00:00Z","surface":"cli","mac":"` + strings.Repeat("ab", 32) + `"}`,
		"malformed MAC":         `{"version":1,"accepted_at":"2026-10-21T09:00:00Z","surface":"cli","mac":"zz"}`,
		"changed after signing": `{"version":1,"accepted_at":"2026-10-21T09:00:00Z","surface":"cli","by":"dev","mac":"` + signed.MAC + `"}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, ConsentFile), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		c := ReadConsent(dir, key)
		if c.Accepted() || c.Verified {
			t.Errorf("%s reads accepted: %+v", name, c)
		}
	}
}
