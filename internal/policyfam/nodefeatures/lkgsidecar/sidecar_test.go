package lkgsidecar

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewFileNormalizesAndSorts(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	f := NewFile("v1.2.3", []string{"Codex", "codex", "  Crush  ", "", "aider"}, time.Time{}, now)
	want := []string{"aider", "codex", "crush"}
	if len(f.Disallow) != len(want) {
		t.Fatalf("Disallow = %v, want %v", f.Disallow, want)
	}
	for i := range want {
		if f.Disallow[i] != want[i] {
			t.Fatalf("Disallow = %v, want %v (sorted, deduped, lowered)", f.Disallow, want)
		}
	}
	if f.WriterVersion != "v1.2.3" {
		t.Errorf("WriterVersion = %q", f.WriterVersion)
	}
	if f.GrantExpiresAt != "" {
		t.Errorf("zero grant expiry must serialize empty, got %q", f.GrantExpiresAt)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	f := NewFile("v1", []string{"codex"}, now.Add(time.Hour), now)
	raw, err := Encode(f)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.Disallowed("codex") || got.Disallowed("aider") {
		t.Errorf("Disallowed after round-trip wrong: %+v", got)
	}
	if got.GrantExpiresAt == "" {
		t.Error("grant expiry lost in round-trip")
	}
}

func TestDecodeRejectsUnknownFieldsAndTrailing(t *testing.T) {
	if _, err := Decode([]byte(`{"schema":1,"disallow":[],"bogus":1}`)); err == nil {
		t.Error("unknown field should be rejected (closed decoder)")
	}
	if _, err := Decode([]byte(`{"schema":1,"disallow":[]} trailing`)); err == nil {
		t.Error("trailing bytes should be rejected")
	}
}

func TestReadFailureTableFailsOpen(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()

	// absent
	if f, reason := Read(filepath.Join(dir, "nope.json"), now); f != nil || reason != ReasonAbsent {
		t.Errorf("absent: f=%v reason=%q", f, reason)
	}
	// empty path
	if f, reason := Read("", now); f != nil || reason != ReasonAbsent {
		t.Errorf("empty path: reason=%q", reason)
	}
	// malformed
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if f, reason := Read(bad, now); f != nil || reason != ReasonMalformed {
		t.Errorf("malformed: reason=%q", reason)
	}
	// expired grant → ignored whole (offboarding guarantee)
	exp := filepath.Join(dir, "exp.json")
	raw, _ := Encode(NewFile("v1", []string{"codex"}, now.Add(-time.Hour), now.Add(-2*time.Hour)))
	if err := os.WriteFile(exp, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if f, reason := Read(exp, now); f != nil || reason != ReasonGrantExpired {
		t.Errorf("expired: f=%v reason=%q", f, reason)
	}
	// schema too new
	tooNew := filepath.Join(dir, "new.json")
	if err := os.WriteFile(tooNew, []byte(`{"schema":99,"disallow":["codex"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if f, reason := Read(tooNew, now); f != nil || reason != ReasonSchemaTooNew {
		t.Errorf("schema-too-new: reason=%q", reason)
	}
	// oversize
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, []byte("{"+strings.Repeat("a", MaxBytes)+"}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, reason := Read(big, now); reason != ReasonOversize {
		t.Errorf("oversize: reason=%q", reason)
	}
}

func TestReadLiveDisallow(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	p := filepath.Join(dir, "features-effective.json")
	raw, _ := Encode(NewFile("v1", []string{"codex", "crush"}, time.Time{}, now))
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	f, reason := Read(p, now)
	if f == nil || reason != ReasonNone {
		t.Fatalf("live read: f=%v reason=%q", f, reason)
	}
	if !f.Disallowed("codex") || !f.Disallowed("CRUSH") || f.Disallowed("claude-code") {
		t.Errorf("Disallowed wrong: %+v", f.Disallow)
	}
}

func TestNilFileDisallowsNothing(t *testing.T) {
	var f *File
	if f.Disallowed("codex") {
		t.Error("nil File must fail open (disallow nothing)")
	}
}
