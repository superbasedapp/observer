package dastconsent

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

func testKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// TestConsentRecord: the accept is its own signed record; the usual
// refusals hold, and a record signed under another domain, another key or
// an older version reads not accepted.
func TestConsentRecord(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "security")
	key := testKey(7)
	if Read(dir, key).Accepted() {
		t.Fatal("no record reads accepted")
	}
	for name, rec := range map[string]func() error{
		"agent surface": func() error { _, err := Record(dir, "agent", "u", time.Now(), key); return err },
		"no time":       func() error { _, err := Record(dir, "cli", "u", time.Time{}, key); return err },
		"no key":        func() error { _, err := Record(dir, "cli", "u", time.Now(), nil); return err },
		"no dir":        func() error { _, err := Record("", "cli", "u", time.Now(), key); return err },
	} {
		if rec() == nil {
			t.Errorf("%s: recorded", name)
		}
	}
	at := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	c, err := Record(dir, "cli", "dev", at, key)
	if err != nil {
		t.Fatal(err)
	}
	got := Read(dir, key)
	if !got.Accepted() || got != c || got.Surface != "cli" || got.Version != Version {
		t.Fatalf("read back %+v, want %+v", got, c)
	}
	if Read(dir, testKey(6)).Accepted() || Read(dir, nil).Accepted() {
		t.Fatal("a record verified under another key, or none")
	}
	if fi, err := os.Stat(filepath.Join(dir, File)); err != nil || (fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/') {
		t.Fatalf("record mode %v %v", fi, err)
	}
	// A hand-edited record (another surface, an older version) fails.
	b, _ := os.ReadFile(filepath.Join(dir, File))
	for _, edit := range []struct{ from, to string }{{`"cli"`, `"dashboard"`}, {fmt.Sprintf(`"version":%d`, Version), `"version":1`}} {
		if err := os.WriteFile(filepath.Join(dir, File), []byte(strings.Replace(string(b), edit.from, edit.to, 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		if Read(dir, key).Accepted() {
			t.Errorf("edited record (%s -> %s) reads accepted", edit.from, edit.to)
		}
	}
	// The same fields signed under another accept's domain do not count.
	forged := Consent{Version: Version, AcceptedAt: at, Surface: "cli", By: "dev"}
	forged.MAC = guardposture.RecordMAC("sbo-osv-db-consent-v1", forged.canonical(), key)
	if err := os.WriteFile(filepath.Join(dir, File), []byte(`{"version":`+strconv.Itoa(Version)+`,"accepted_at":"2026-11-04T10:00:00Z","surface":"cli","by":"dev","mac":"`+forged.MAC+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if Read(dir, key).Accepted() {
		t.Fatal("a record signed under another accept's domain reads accepted")
	}
	if !strings.Contains(Text, "localhost") || !strings.Contains(Text, "/.env") || !strings.Contains(Text, "nothing leaves this machine") {
		t.Errorf("the accept text does not say what is sent and where: %s", Text)
	}
}

// TestNoForbiddenImports: the record package reads and writes one file;
// no network, database, process or fsnotify.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "net", "net/http", "os/exec", "github.com/fsnotify/fsnotify"},
		ForbiddenTrees: []string{
			"github.com/marmutapp/superbased-observer/internal/store",
			"github.com/marmutapp/superbased-observer/internal/secdastnet",
		},
		Reason: "the DAST accept record links no lane",
	})
}
