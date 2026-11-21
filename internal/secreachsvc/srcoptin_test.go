package secreachsvc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSourceOptInRecordReadWithdraw(t *testing.T) {
	dir := t.TempDir()
	key := []byte("0123456789abcdef0123456789abcdef")
	h1, h2 := strings.Repeat("a", 64), strings.Repeat("b", 64)
	at := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)

	if ReadSourceOptIn(dir, h1, key).OptedIn() {
		t.Fatal("opted in with no record")
	}
	if _, err := RecordSourceOptIn(dir, h1, "agent", "", false, at, key); err == nil {
		t.Error("an unknown surface recorded")
	}
	if _, err := RecordSourceOptIn(dir, "nothex", "cli", "", false, at, key); err == nil {
		t.Error("a bad root hash recorded")
	}
	if _, err := RecordSourceOptIn(dir, h1, "cli", "", false, at, nil); err == nil {
		t.Error("recorded without a key")
	}
	if _, err := RecordSourceOptIn(dir, h1, "cli", "dev", false, at, key); err != nil {
		t.Fatal(err)
	}
	o := ReadSourceOptIn(dir, h1, key)
	if !o.OptedIn() || o.UnisolatedAllowed() {
		t.Fatalf("after record: %+v", o)
	}
	if ReadSourceOptIn(dir, h2, key).OptedIn() {
		t.Error("another project reads opted in")
	}
	if ReadSourceOptIn(dir, h1, []byte("another key 0123456789abcdef0000")).OptedIn() {
		t.Error("an entry verified under another key")
	}
	// Windows has no Unix permission bits; os.Stat reports 0666 there.
	if fi, err := os.Stat(filepath.Join(dir, SourceOptInFile)); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Errorf("record mode: %v %v", fi, err)
	}

	// A hand edit (the override turned on, or the entry copied to another
	// project) does not verify.
	b, _ := os.ReadFile(filepath.Join(dir, SourceOptInFile))
	var raw map[string]map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	raw[h1]["allow_unisolated"] = true
	raw[h2] = raw[h1]
	b, _ = json.Marshal(raw)
	if err := os.WriteFile(filepath.Join(dir, SourceOptInFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if ReadSourceOptIn(dir, h1, key).OptedIn() || ReadSourceOptIn(dir, h2, key).OptedIn() {
		t.Error("a hand-edited or copied entry verified")
	}

	if _, err := RecordSourceOptIn(dir, h1, "dashboard", "", true, at, key); err != nil {
		t.Fatal(err)
	}
	if o := ReadSourceOptIn(dir, h1, key); !o.UnisolatedAllowed() || o.Surface != "dashboard" {
		t.Errorf("override not recorded: %+v", o)
	}
	if err := WithdrawSourceOptIn(dir, h2); err != nil {
		t.Fatal(err)
	}
	if err := WithdrawSourceOptIn(dir, h1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, SourceOptInFile)); !os.IsNotExist(err) {
		t.Errorf("the last withdraw left the file: %v", err)
	}
	if err := WithdrawSourceOptIn(dir, h1); err != nil {
		t.Errorf("withdrawing nothing: %v", err)
	}
}
