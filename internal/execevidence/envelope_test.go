package execevidence

import (
	"strings"
	"testing"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

func sample() Envelope {
	return Envelope{
		RunID:    "run-1",
		Producer: Producer{Kind: KindTerminalRun, Component: "terminals.sandbox", ComponentVersion: "1.40.0"},
		Artifact: Artifact{Name: "bwrap", Version: "0.9.0"},
		Isolation: Isolation{
			Class: vocab.ClassProcess, Stack: []string{"bwrap"}, EgressTier: vocab.TierInternet,
			CaptureLevel: vocab.CaptureFull, CaptureRule: "C6", GatewayGuarded: true,
			CaptureOrigin: vocab.OriginSandboxed, NativeSandboxState: vocab.NativeNotApplicable,
			Verification: vocab.VerifiedLive, KeyCustody: vocab.CustodyHostBound,
		},
	}
}

func TestSealAndVerify(t *testing.T) {
	e := sample()
	d, err := e.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if len(d) != 64 || !e.Verify(d) {
		t.Fatalf("digest %q does not verify", d)
	}
	// The org reference is not part of the digest.
	e.OrgRowRef = "terminal_run_rows:run-1"
	if !e.Verify(d) {
		t.Fatal("the org reference changed the digest")
	}
}

// TestEveryFieldMovesTheDigest: changing any recorded fact changes the
// digest, so a stored digest detects an edited row.
func TestEveryFieldMovesTheDigest(t *testing.T) {
	base := sample().Digest()
	for name, mut := range map[string]func(*Envelope){
		"run id":          func(e *Envelope) { e.RunID = "run-2" },
		"producer kind":   func(e *Envelope) { e.Producer.Kind = KindIsolatedRun },
		"component":       func(e *Envelope) { e.Producer.Component = "isolation" },
		"version":         func(e *Envelope) { e.Producer.ComponentVersion = "1.41.0" },
		"artifact":        func(e *Envelope) { e.Artifact.Version = "0.10.0" },
		"artifact auth":   func(e *Envelope) { e.Artifact.VersionAuthenticated = true },
		"class":           func(e *Envelope) { e.Isolation.Class = vocab.ClassNone },
		"stack":           func(e *Envelope) { e.Isolation.Stack = nil },
		"tier":            func(e *Envelope) { e.Isolation.EgressTier = vocab.TierHost },
		"capture":         func(e *Envelope) { e.Isolation.CaptureLevel = vocab.CaptureProxyAndTranscripts },
		"rule":            func(e *Envelope) { e.Isolation.CaptureRule = "C5" },
		"guarded":         func(e *Envelope) { e.Isolation.GatewayGuarded = false },
		"origin":          func(e *Envelope) { e.Isolation.CaptureOrigin = vocab.OriginLocal },
		"degraded":        func(e *Envelope) { e.Isolation.CaptureDegraded = true },
		"native":          func(e *Envelope) { e.Isolation.NativeSandboxState = vocab.NativeOn },
		"verification":    func(e *Envelope) { e.Isolation.Verification = vocab.VerifiedDoc },
		"custody":         func(e *Envelope) { e.Isolation.KeyCustody = vocab.CustodyHomeRelay },
		"length boundary": func(e *Envelope) { e.RunID, e.Producer.Component = "run-1t", "erminals.sandbox" },
	} {
		e := sample()
		mut(&e)
		if e.Digest() == base {
			t.Errorf("%s: digest unchanged", name)
		}
	}
}

func TestValidateRefusesUnknownValues(t *testing.T) {
	for name, mut := range map[string]func(*Envelope){
		"no run id":    func(e *Envelope) { e.RunID = " " },
		"kind":         func(e *Envelope) { e.Producer.Kind = "job" },
		"component":    func(e *Envelope) { e.Producer.Component = "" },
		"class":        func(e *Envelope) { e.Isolation.Class = "vm" },
		"tier":         func(e *Envelope) { e.Isolation.EgressTier = "open" },
		"capture":      func(e *Envelope) { e.Isolation.CaptureLevel = "most" },
		"origin":       func(e *Envelope) { e.Isolation.CaptureOrigin = "cloud" },
		"native":       func(e *Envelope) { e.Isolation.NativeSandboxState = "maybe" },
		"verification": func(e *Envelope) { e.Isolation.Verification = "beta" },
		"custody":      func(e *Envelope) { e.Isolation.KeyCustody = "vault" },
		"digest":       func(e *Envelope) { e.Artifact.Digest = "abc" },
		"stack id":     func(e *Envelope) { e.Isolation.Stack = []string{"a|b"} },
	} {
		e := sample()
		mut(&e)
		if _, err := e.Seal(); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if e.Verify(e.Digest()) {
			t.Errorf("%s: an invalid envelope verifies", name)
		}
	}
	// Empty fields are "not recorded", which is valid.
	e := Envelope{RunID: "r", Producer: Producer{Kind: KindTerminalRun, Component: "terminals"}}
	if _, err := e.Seal(); err != nil {
		t.Fatalf("an envelope with nothing recorded: %v", err)
	}
	if !strings.HasPrefix(digestDomain, "sbo-") {
		t.Fatal("digest domain")
	}
}
