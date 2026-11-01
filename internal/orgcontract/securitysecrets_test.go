package orgcontract

import (
	"strings"
	"testing"
)

// fakeSecretScan stands in for internal/scrub: one certain secret value and
// one entropy-only blob.
const fakeSecret = "SECRETVALUEq7w8e9r0t1y2"

var fakeSecretScan = SecuritySecretScan{
	Certain: func(s string) bool { return strings.Contains(s, fakeSecret) },
	Any:     func(s string) bool { return strings.Contains(s, fakeSecret) || strings.Contains(s, "ENTROPYBLOB") },
	Mask:    func(s string) string { return strings.ReplaceAll(s, fakeSecret, "[REDACTED:fake]") },
}

// TestGateSecuritySecrets pins ruling P-055's gate: the evidence is masked,
// a raw path or alias holding a secret is cleared, an always-class field
// holding one drops the row, and an unwired scan fails closed.
func TestGateSecuritySecrets(t *testing.T) {
	base := SecurityFindingRow{FindingRef: strings.Repeat("a", 32), RuleID: "S-721", Category: "secret", Severity: "high", Status: "open", LastSeen: "2026-10-22T00:00:00Z"}

	r := base
	r.EvidenceRedacted = "key = " + fakeSecret + " here"
	r.RelPath = "keys/" + fakeSecret + ".txt"
	r.PathAliases = []string{"old/" + fakeSecret, "old/clean.go"}
	if !GateSecuritySecrets(&r, fakeSecretScan) {
		t.Fatal("a row with raw-class secrets was dropped; it must ship masked")
	}
	if r.EvidenceRedacted != "key = [REDACTED:fake] here" || r.RelPath != "" || len(r.PathAliases) != 1 || r.PathAliases[0] != "old/clean.go" {
		t.Errorf("raw fields after the gate: %+v", r)
	}

	r = base
	r.EvidenceRedacted = "an ENTROPYBLOB survives masking"
	if !GateSecuritySecrets(&r, fakeSecretScan) || r.EvidenceRedacted != "" {
		t.Errorf("evidence still secret-shaped after masking must be cleared: %q", r.EvidenceRedacted)
	}

	// A clipped window at the cap ends in a piece no detector recognises.
	r = base
	r.EvidenceRedacted = strings.Repeat("x", maxSecEvidence-11) + " tail " + fakeSecret[:5]
	if !GateSecuritySecrets(&r, fakeSecretScan) || strings.Contains(r.EvidenceRedacted, fakeSecret[:5]) {
		t.Errorf("the clipped edge token survived: %q", r.EvidenceRedacted)
	}

	r = base
	r.Model = fakeSecret
	if GateSecuritySecrets(&r, fakeSecretScan) {
		t.Error("an always-class field holding a secret must drop the row")
	}
	r = base
	r.VerdictIDs = []string{fakeSecret}
	if GateSecuritySecrets(&r, fakeSecretScan) {
		t.Error("an always-class list holding a secret must drop the row")
	}

	c := AIChangeRecordRow{CommitIdentityHash: strings.Repeat("c", 64), Paths: []string{"a/" + fakeSecret}}
	if !GateSecuritySecrets(&c, fakeSecretScan) || c.Paths != nil {
		t.Errorf("change record paths after the gate: %+v", c.Paths)
	}

	r = base
	if GateSecuritySecrets(&r, SecuritySecretScan{}) {
		t.Error("a zero scan must refuse the row")
	}
}

// TestSecurityWireInvisibleCharacters pins lane SEC-E2 audit finding 10: a
// path holding a bidi control, a zero-width character, a C1 control or a
// byte order mark is refused, and the evidence window drops the format
// characters and blanks the controls, in the shared normalization both the
// node and the server run.
func TestSecurityWireInvisibleCharacters(t *testing.T) {
	for _, p := range []string{
		"src/a\u202egp.go", // right-to-left override
		"src/a\u2066b.go",  // left-to-right isolate
		"src/a\u200bb.go",  // zero-width space
		"src/a\u200db.go",  // zero-width joiner
		"src/a\u0085b.go",  // C1 next line
		"src/a\u009bb.go",  // C1 control sequence introducer
		"src/\ufeffa.go",   // byte order mark
		"src/a\u061cb.go",  // Arabic letter mark
		"src/a\x7fb.go",    // DEL
	} {
		if SecurityRelPathOK(p) {
			t.Errorf("path %q accepted", p)
		}
	}
	if !SecurityRelPathOK("src/naïve/日本.go") {
		t.Error("a plain non-ASCII path was refused")
	}
	got := secEvidence("a\u202eb\u200bc\u0085d\te\x01f")
	if got != "abc d\te f" {
		t.Errorf("evidence = %q", got)
	}
	r, ok := NormalizeSecurityFinding(SecurityFindingRow{
		FindingRef: strings.Repeat("a", 32), RuleID: "S-721", Category: "secret", Severity: "high", Status: "open",
		LastSeen: "2026-10-22T00:00:00Z", RelPath: "src/\u202egp.go", PathAliases: []string{"ok.go", "x\u200b.go"},
		EvidenceRedacted: "x\u2067y",
	})
	if !ok || r.RelPath != "" || len(r.PathAliases) != 1 || r.EvidenceRedacted != "xy" {
		t.Errorf("normalized: %+v", r)
	}
}
