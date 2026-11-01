package sandboxselect

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

func bwrapRow(t *testing.T) sandboxbackend.Capability {
	t.Helper()
	r, ok := sandboxbackend.Get(sandboxbackend.BackendBwrap)
	if !ok {
		t.Fatal("no bwrap row")
	}
	return r
}

// TestCaptureRules: one case per row of section 4.4's table C1 to C8 (and
// the conservative fallback), each proving the row is the one that fired.
func TestCaptureRules(t *testing.T) {
	bw := bwrapRow(t)
	inBox := bw
	inBox.Capture.HookPath = sandboxbackend.HookInBoxObserver
	provider := bw
	provider.Net.Enforcer = sandboxbackend.EnforcerProvider
	k8s := bw
	k8s.Net.Enforcer = sandboxbackend.EnforcerK8sPolicy
	noBlock := bw
	noBlock.Net.ProviderHostBlock = false
	noBoundary := bw
	noBoundary.Net.Enforcer = sandboxbackend.EnforcerNone
	claimedProxyOnly := bw
	claimedProxyOnly.Net.EgressSource = map[vocab.Tier]vocab.ClassSource{vocab.TierProxyOnly: vocab.SourceClaimed}
	lowCeiling := bw
	lowCeiling.Capture.Ceiling = vocab.CaptureTranscriptsOnly

	full, pt := vocab.CaptureFull, vocab.CaptureProxyAndTranscripts
	for _, tc := range []struct {
		name  string
		in    CaptureInput
		level vocab.CaptureLevel
		rule  string
		block bool
	}{
		{"C1 hooks judged in the box", CaptureInput{Row: inBox, Tier: vocab.TierNone, ProxyRouted: true}, pt, "C1", false},
		{"C2 provider-injected key", CaptureInput{Row: bw, Tier: vocab.TierProxyOnly, Custody: vocab.CustodyProviderInjected, ProxyRouted: true}, pt, "C2", false},
		{"C3 tool not proxy-routed keeps hooks and transcripts", CaptureInput{Row: bw, Tier: vocab.TierHost, CredentialInReach: true}, vocab.CaptureTranscriptsOnly, "C3", false},
		{"C3 unrouted on internet is never full", CaptureInput{Row: bw, Tier: vocab.TierInternet, CredentialInReach: true}, vocab.CaptureTranscriptsOnly, "C3", false},
		{"C4 no credential in reach", CaptureInput{Row: bw, Tier: vocab.TierHost, ProxyRouted: true}, full, "C4", false},
		{"C5 proxy_only measured", CaptureInput{Row: bw, Tier: vocab.TierProxyOnly, ProxyRouted: true, CredentialInReach: true}, full, "C5", false},
		{"C5 none measured", CaptureInput{Row: bw, Tier: vocab.TierNone, ProxyRouted: true, CredentialInReach: true}, full, "C5", false},
		{"C6 internet through the gateway with the block", CaptureInput{Row: bw, Tier: vocab.TierInternet, ProxyRouted: true, CredentialInReach: true}, full, "C6", true},
		{"C6 internet through the gateway without the block", CaptureInput{Row: noBlock, Tier: vocab.TierInternet, ProxyRouted: true, CredentialInReach: true}, pt, "C6", false},
		{"C7 provider-owned egress", CaptureInput{Row: provider, Tier: vocab.TierInternet, ProxyRouted: true, CredentialInReach: true}, pt, "C7", false},
		{"C7 NetworkPolicy egress", CaptureInput{Row: k8s, Tier: vocab.TierInternet, ProxyRouted: true, CredentialInReach: true}, pt, "C7", false},
		{"C8 host network", CaptureInput{Row: bw, Tier: vocab.TierHost, ProxyRouted: true, CredentialInReach: true}, pt, "C8", false},
		{"C8 no network boundary", CaptureInput{Row: noBoundary, Tier: vocab.TierInternet, ProxyRouted: true, CredentialInReach: true}, pt, "C8", false},
		{"fallback: proxy_only only claimed", CaptureInput{Row: claimedProxyOnly, Tier: vocab.TierProxyOnly, ProxyRouted: true, CredentialInReach: true}, pt, RuleUnmatched, false},
		{"ceiling caps C4", CaptureInput{Row: lowCeiling, Tier: vocab.TierNone, ProxyRouted: true}, vocab.CaptureTranscriptsOnly, "C4", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ComputeCapture(tc.in)
			if got.Level != tc.level || got.Rule != tc.rule || got.ProviderBlock != tc.block {
				t.Fatalf("got %+v, want level %s rule %s block %v", got, tc.level, tc.rule, tc.block)
			}
		})
	}
}

// Mutation proof (9), its pure half: removing the provider-host block from
// the bwrap row makes an internet run with a bound credential compute
// proxy_and_transcripts, and the label says "full (gateway-guarded)" only
// while the block is on.
func TestRemovingTheBlockLowersCapture(t *testing.T) {
	bw := bwrapRow(t)
	in := CaptureInput{Row: bw, Tier: vocab.TierInternet, Custody: vocab.CustodyHostBound, ProxyRouted: true, CredentialInReach: true}
	on := ComputeCapture(in)
	if on.Level != vocab.CaptureFull || !on.ProviderBlock || CaptureLabel(on) != "full (gateway-guarded)" {
		t.Fatalf("with the block: %+v %q", on, CaptureLabel(on))
	}
	bw.Net.ProviderHostBlock = false
	in.Row = bw
	off := ComputeCapture(in)
	if off.Level != vocab.CaptureProxyAndTranscripts || off.ProviderBlock {
		t.Fatalf("without the block: %+v", off)
	}
}

func TestCaptureByTier(t *testing.T) {
	got := CaptureByTier(bwrapRow(t), vocab.CustodyHostBound, true, true, "")
	want := map[vocab.Tier]vocab.CaptureLevel{
		vocab.TierHost: vocab.CaptureProxyAndTranscripts, vocab.TierInternet: vocab.CaptureFull,
		vocab.TierProxyOnly: vocab.CaptureFull, vocab.TierNone: vocab.CaptureFull,
	}
	for tier, lvl := range want {
		if got[tier].Level != lvl {
			t.Errorf("%s: %s, want %s", tier, got[tier].Level, lvl)
		}
	}
}

// TestProviderDirectRules: one case per row of the DEC-9 table
// (providerDirectRules) plus the default and the rows it must leave alone.
func TestProviderDirectRules(t *testing.T) {
	bw := bwrapRow(t)
	noBlock := bw
	noBlock.Net.ProviderHostBlock = false
	provider := bw
	provider.Net.Enforcer = sandboxbackend.EnforcerProvider
	lowCeiling := bw
	lowCeiling.Capture.Ceiling = vocab.CaptureProxyAndTranscripts

	full, pt, to := vocab.CaptureFull, vocab.CaptureProxyAndTranscripts, vocab.CaptureTranscriptsOnly
	c6 := CaptureInput{Row: bw, Tier: vocab.TierInternet, ProxyRouted: true, CredentialInReach: true}
	with := func(in CaptureInput, p vocab.ProviderDirect) CaptureInput { in.ProviderDirect = p; return in }
	for _, tc := range []struct {
		name    string
		in      CaptureInput
		level   vocab.CaptureLevel
		rule    string
		block   bool
		guarded bool
		policy  vocab.ProviderDirect
	}{
		{"unset is C6 as today", c6, full, "C6", true, true, ""},
		{"capture_rule is C6 as today", with(c6, vocab.ProviderDirectCaptureRule), full, "C6", true, true, ""},
		{"unknown value reads capture_rule", with(c6, "bogus"), full, "C6", true, true, ""},
		{"allow drops a C6 run to proxy_and_transcripts with no block", with(c6, vocab.ProviderDirectAllow), pt, "C6", false, false, vocab.ProviderDirectAllow},
		{"allow keeps a C4 run full (no credential in reach)", with(CaptureInput{Row: bw, Tier: vocab.TierInternet, ProxyRouted: true}, vocab.ProviderDirectAllow), full, "C4", false, false, ""},
		{"allow keeps a C5 proxy_only run full", with(CaptureInput{Row: bw, Tier: vocab.TierProxyOnly, ProxyRouted: true, CredentialInReach: true}, vocab.ProviderDirectAllow), full, "C5", false, false, ""},
		{"refuse_all on a C6 run is C6's block already", with(c6, vocab.ProviderDirectRefuseAll), full, "C6", true, true, ""},
		{"refuse_all blocks a C4 internet run", with(CaptureInput{Row: bw, Tier: vocab.TierInternet, ProxyRouted: true}, vocab.ProviderDirectRefuseAll), full, "C4", true, false, vocab.ProviderDirectRefuseAll},
		{"refuse_all blocks an unrouted internet run (C3)", with(CaptureInput{Row: bw, Tier: vocab.TierInternet, CredentialInReach: true}, vocab.ProviderDirectRefuseAll), to, "C3", true, false, vocab.ProviderDirectRefuseAll},
		{"refuse_all keeps the block past a lowering ceiling", with(CaptureInput{Row: lowCeiling, Tier: vocab.TierInternet, ProxyRouted: true, CredentialInReach: true}, vocab.ProviderDirectRefuseAll), pt, "C6", true, false, vocab.ProviderDirectRefuseAll},
		{"refuse_all cannot block on a row without the block", with(CaptureInput{Row: noBlock, Tier: vocab.TierInternet, ProxyRouted: true, CredentialInReach: true}, vocab.ProviderDirectRefuseAll), pt, "C6", false, false, ""},
		{"refuse_all cannot block provider-owned egress", with(CaptureInput{Row: provider, Tier: vocab.TierInternet, ProxyRouted: true, CredentialInReach: true}, vocab.ProviderDirectRefuseAll), pt, "C7", false, false, ""},
		{"refuse_all leaves the proxy_only tier alone", with(CaptureInput{Row: bw, Tier: vocab.TierProxyOnly, ProxyRouted: true, CredentialInReach: true}, vocab.ProviderDirectRefuseAll), full, "C5", false, false, ""},
		{"refuse_all leaves the host tier alone", with(CaptureInput{Row: bw, Tier: vocab.TierHost, ProxyRouted: true, CredentialInReach: true}, vocab.ProviderDirectRefuseAll), pt, "C8", false, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ComputeCapture(tc.in)
			if got.Level != tc.level || got.Rule != tc.rule || got.ProviderBlock != tc.block || got.GatewayGuarded != tc.guarded || got.ProviderDirect != tc.policy {
				t.Fatalf("got %+v, want level %s rule %s block %v guarded %v policy %q", got, tc.level, tc.rule, tc.block, tc.guarded, tc.policy)
			}
		})
	}
}

// TestAllowNeverLabelsFull: under allow no tier of any row is labelled full
// through the gateway block (DEC-9: no surface claims full capture for a
// run whose full capture rested on the block).
func TestAllowNeverLabelsFull(t *testing.T) {
	for _, id := range sandboxbackend.IDs() {
		row, _ := sandboxbackend.Get(id)
		for tier, r := range CaptureByTier(row, vocab.CustodyHostBound, true, true, vocab.ProviderDirectAllow) {
			if r.ProviderBlock || r.GatewayGuarded || CaptureLabel(r) == "full (gateway-guarded)" {
				t.Errorf("%s %s: %+v", row.ID, tier, r)
			}
		}
	}
}
