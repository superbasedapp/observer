//go:build !sbo_omit_terminals

package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/execevidence"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// TestRunIsolationRecordSealsTheEnvelope: the recorder stores the run's
// isolation facts with the digest of its execution evidence envelope
// (roadmap F0-13); a run that recorded nothing gets no digest, and an
// unknown enum keeps its facts but gets no digest either.
func TestRunIsolationRecordSealsTheEnvelope(t *testing.T) {
	run := termrun.Run{RunID: "r1", Isolation: termrun.Isolation{
		Class: "process", Stack: []string{"bwrap"}, EgressTier: "internet", CaptureLevel: "full",
		CaptureRule: "C6", CaptureOrigin: "sandboxed", Verification: "live", KeyCustody: "host_bound",
	}}
	rec := runIsolationRecord(run)
	env := execevidence.Envelope{
		RunID:    "r1",
		Producer: execevidence.Producer{Kind: execevidence.KindTerminalRun, Component: "terminals.sandbox", ComponentVersion: version},
		Isolation: execevidence.Isolation{
			Class: vocab.ClassProcess, Stack: []string{"bwrap"}, EgressTier: vocab.TierInternet, CaptureLevel: vocab.CaptureFull,
			CaptureRule: "C6", GatewayGuarded: true, CaptureOrigin: vocab.OriginSandboxed,
			Verification: vocab.VerifiedLive, KeyCustody: vocab.CustodyHostBound,
		},
	}
	if rec.EvidenceDigest == "" || !env.Verify(rec.EvidenceDigest) || rec.Class != "process" {
		t.Fatalf("record %+v does not carry the envelope's digest", rec)
	}
	// Audit finding P-006 (3): the digest is recomputable from what the row
	// stores, with nothing taken from the recorder's own knowledge.
	if !recomputeFromRecord("r1", rec).Verify(rec.EvidenceDigest) {
		t.Fatalf("the stored record %+v does not recompute its own digest", rec)
	}
	if got := runIsolationRecord(termrun.Run{RunID: "r2"}); got.EvidenceDigest != "" || got.Class != "" {
		t.Fatalf("a run that recorded nothing: %+v", got)
	}
	bad := run
	bad.Isolation.CaptureLevel = "most"
	if got := runIsolationRecord(bad); got.EvidenceDigest != "" || got.CaptureLevel != "most" {
		t.Fatalf("an invalid envelope: %+v", got)
	}
	unsandboxed := runIsolationRecord(termrun.Run{RunID: "r3", Isolation: termrun.Isolation{Class: "none", CaptureOrigin: "local"}})
	if unsandboxed.EvidenceDigest == "" {
		t.Fatal("an unsandboxed run's true facts were not sealed")
	}
}

// recomputeFromRecord rebuilds the envelope from a stored record only, the
// way an auditor reading terminal_run would.
func recomputeFromRecord(runID string, rec store.TerminalRunIsolation) execevidence.Envelope {
	return execevidence.Envelope{
		RunID: runID,
		Producer: execevidence.Producer{
			Kind: execevidence.ProducerKind(rec.EvidenceProducer), Component: rec.EvidenceComponent,
			ComponentVersion: rec.EvidenceComponentVersion,
		},
		Isolation: execevidence.Isolation{
			Class: vocab.IsoClass(rec.Class), Stack: rec.Stack, EgressTier: vocab.Tier(rec.EgressTier),
			CaptureLevel: vocab.CaptureLevel(rec.CaptureLevel), CaptureRule: rec.CaptureRule,
			GatewayGuarded: rec.CaptureRule == "C6" && rec.CaptureLevel == string(vocab.CaptureFull),
			CaptureOrigin:  vocab.CaptureOrigin(rec.CaptureOrigin), CaptureDegraded: rec.CaptureDegraded,
			NativeSandboxState: vocab.NativeSandboxState(rec.NativeSandboxState),
			Verification:       vocab.Verification(rec.Verification), KeyCustody: vocab.KeyCustody(rec.KeyCustody),
		},
	}
}
