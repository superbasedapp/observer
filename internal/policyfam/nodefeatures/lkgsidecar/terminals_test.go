package lkgsidecar

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDisallowSidecarStaysReadableByOlderBinaries (audit follow-up F2): the
// disallow sidecar's shape is unchanged, so a File encoded by this build
// decodes under the strict decoder an older binary runs, and the terminals
// rule never appears in it.
func TestDisallowSidecarStaysReadableByOlderBinaries(t *testing.T) {
	raw, err := Encode(NewFile("v", []string{"codex"}, time.Time{}, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "terminals") {
		t.Fatalf("the disallow sidecar carries the terminals rule: %s", raw)
	}
	if _, err := Decode(raw); err != nil {
		t.Fatal(err)
	}
}

// TestTerminalsFileRoundTripAndFailureTable: the sibling file round-trips,
// and an absent, malformed or too-new file reports its reason.
func TestTerminalsFileRoundTripAndFailureTable(t *testing.T) {
	dir := t.TempDir()
	side := filepath.Join(dir, "features-effective.json")
	p := TerminalsPath(side)
	if filepath.Dir(p) != dir || filepath.Base(p) != TerminalsFilename || TerminalsPath("") != "" {
		t.Fatalf("path %q", p)
	}
	if f, why := ReadTerminals(p); f != nil || why != ReasonAbsent {
		t.Fatalf("absent: %v %q", f, why)
	}
	raw, err := EncodeTerminals(NewTerminalsFile("v", &Terminals{Enabled: true, SandboxRequired: true}, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if f, why := ReadTerminals(p); f == nil || why != ReasonNone || f.Terminals == nil || !f.Terminals.SandboxRequired {
		t.Fatalf("round trip: %+v %q", f, why)
	}
	for body, want := range map[string]string{
		`{"schema":1,"terminals":null,"extra":1}`: ReasonMalformed,
		`{"schema":9,"terminals":null}`:           ReasonSchemaTooNew,
	} {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if f, why := ReadTerminals(p); f != nil || why != want {
			t.Fatalf("%s: %v %q, want %q", body, f, why, want)
		}
	}
}
