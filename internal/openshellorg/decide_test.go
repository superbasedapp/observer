package openshellorg

import (
	"testing"
	"time"
)

func goodCall() CallFacts {
	b := liveBox()
	return CallFacts{
		RPC: RPCExecInteractive, TokenOK: true, Purpose: PurposeAttach, RunID: "run1", BoxRunID: "run1", MemberID: "m1",
		BoxName: "obsbox", RecordedBoxName: "obsbox", Enabled: true, Drain: DrainActive,
		Grant:  GrantFacts{Found: true, MemberID: "m1", ExpiresAt: t0.Add(time.Hour), AgentKeyFP: "fp"},
		Member: MemberNow{ID: "m1", Active: true, Allowed: true, AgentKeyFP: "fp"},
		Box:    b, CreatedAt: t0.Add(-time.Minute), MaxRunMinutes: 120, Quotas: DefaultQuotas(),
		Usage: Usage{MemberLive: 1, OrgLive: 1}, Now: t0,
	}
}

func TestDecideCallTable(t *testing.T) {
	cases := []struct {
		name   string
		mut    func(f *CallFacts)
		rule   string
		act    CallAction
		reason Reason
	}{
		{"F4 exec allowed", func(*CallFacts) {}, "F4", CallForward, ReasonNone},
		{"F0 token", func(f *CallFacts) { f.TokenOK = false }, "F0", "", ReasonRunTokenInvalid},
		{"F0 off", func(f *CallFacts) { f.Enabled = false }, "F0", "", ReasonOff},
		{"F0 draining", func(f *CallFacts) { f.Drain = DrainDraining }, "F0", "", ReasonDraining},
		{"F0 grant revoked", func(f *CallFacts) { f.Grant.RevokedAt = t0 }, "F0", "", ReasonSigninRevoked},
		{"F0 member disabled", func(f *CallFacts) { f.Member.Active = false }, "F0", "", ReasonMemberNotAllowed},
		{"F0 another member's box", func(f *CallFacts) { f.Box.MemberID = "m2" }, "F0", "", ReasonRunNotYours},
		{"F0 superseded run after resume", func(f *CallFacts) { f.Box.ActiveRunID = "run9" }, "F0", "", ReasonRunNotYours},
		{"F0 held", func(f *CallFacts) { f.Box.State = BoxHeld }, "F0", "", ReasonRunHeld},
		{"F0 resuming", func(f *CallFacts) { f.Box.State = BoxResuming }, "F0", "", ReasonRunHeld},
		{"F0 reaped", func(f *CallFacts) { f.Box.State = BoxReaped }, "F0", "", ReasonRunUnknown},
		{"F1 health needs only the token", func(f *CallFacts) {
			f.RPC, f.Grant.Found, f.Enabled = RPCHealth, false, false
		}, "F1", CallHealth, ReasonNone},
		{"F2 create", func(f *CallFacts) { f.RPC, f.Purpose, f.Box.State = RPCCreateSandbox, PurposeCreate, BoxMinted }, "F2", CallCreate, ReasonNone},
		{"F2 create twice", func(f *CallFacts) { f.RPC, f.Purpose = RPCCreateSandbox, PurposeCreate }, "F2", "", ReasonRunUnknown},
		{"F2 create with an attach token", func(f *CallFacts) { f.RPC, f.Box.State = RPCCreateSandbox, BoxMinted }, "F2", "", ReasonRPCNotAllowed},
		{"F2 over quota", func(f *CallFacts) {
			f.RPC, f.Purpose, f.Box.State, f.Usage.OrgLive = RPCCreateSandbox, PurposeCreate, BoxMinted, 21
		}, "F2", "", ReasonQuotaConcurrent},
		{"F3 get", func(f *CallFacts) { f.RPC = RPCGetSandbox }, "F3", CallForward, ReasonNone},
		{"F3 another box", func(f *CallFacts) { f.RPC, f.BoxName = RPCWatchSandbox, "obsother" }, "F3", "", ReasonRunNotYours},
		{"F4a clone", func(f *CallFacts) { f.RPC, f.Purpose, f.CloneArgv = RPCClone, PurposeCreate, true }, "F4a", CallCloneBracket, ReasonNone},
		{"F4a clone twice", func(f *CallFacts) {
			f.RPC, f.Purpose, f.CloneArgv, f.ClonedAt = RPCClone, PurposeCreate, true, t0
		}, "F4a", "", ReasonRPCNotAllowed},
		{"F4a no clone recorded", func(f *CallFacts) { f.RPC, f.Purpose = RPCClone, PurposeCreate }, "F4a", "", ReasonRPCNotAllowed},
		{"F4 exec while the provider is attached", func(f *CallFacts) { f.ProviderReadyAt = t0 }, "F4", "", ReasonRPCNotAllowed},
		{"F4 exec before the clone", func(f *CallFacts) { f.CloneArgv = true }, "F4", "", ReasonRPCNotAllowed},
		{"F4 exec after the detach", func(f *CallFacts) {
			f.CloneArgv, f.ProviderReadyAt, f.ProviderDetachedAt = true, t0, t0
		}, "F4", CallForward, ReasonNone},
		{"F4 past max run", func(f *CallFacts) { f.CreatedAt = t0.Add(-3 * time.Hour) }, "F4", "", ReasonRunUnknown},
		{"F4 teardown token cannot exec", func(f *CallFacts) { f.Purpose = PurposeTeardown }, "F4", "", ReasonRPCNotAllowed},
		{"F6 delete", func(f *CallFacts) { f.RPC, f.Purpose = RPCDeleteSandbox, PurposeTeardown }, "F6", CallDelete, ReasonNone},
		{"F6 delete with an attach token", func(f *CallFacts) { f.RPC = RPCDeleteSandbox }, "F6", "", ReasonRPCNotAllowed},
		{"F6 needs collect", func(f *CallFacts) {
			f.RPC, f.Purpose, f.Box.ReturnToNode = RPCDeleteSandbox, PurposeTeardown, false
		}, "F6", "", ReasonTeardownNeedsCollect},
		{"F7 ListSandboxes", func(f *CallFacts) { f.RPC = "ListSandboxes" }, "F7", "", ReasonRPCNotAllowed},
		{"F7 ForwardTcp", func(f *CallFacts) { f.RPC = "ForwardTcp" }, "F7", "", ReasonRPCNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := goodCall()
			tc.mut(&f)
			rule, act, r := DecideCall(f)
			if rule != tc.rule || act != tc.act || r != tc.reason {
				t.Fatalf("got %s %s %s, want %s %s %s", rule, act, r, tc.rule, tc.act, tc.reason)
			}
		})
	}
}

func TestEventTable(t *testing.T) {
	for _, row := range eventTable {
		for _, s := range AllBoxStates() {
			want := ReasonIllegalTransition
			for _, f := range row.From {
				if f == s {
					want = ReasonNone
				}
			}
			if got := CheckEvent(row.Event, s); got != want {
				t.Fatalf("%s from %s: %s", row.Event, s, got)
			}
		}
	}
	if CheckEvent("reaped", BoxCreated) != ReasonIllegalTransition {
		t.Fatal("an unknown event passed")
	}
}

func TestEventCallTable(t *testing.T) {
	cases := []struct {
		name string
		ev   FrontEvent
		s    BoxState
		p    Purpose
		f0   Reason
		want Reason
	}{
		{"created by a create token", EventCreated, BoxMinted, PurposeCreate, ReasonNone, ReasonNone},
		{"created by an attach token", EventCreated, BoxMinted, PurposeAttach, ReasonNone, ReasonRPCNotAllowed},
		{"cloned by a revoked member", EventCloned, BoxCreated, PurposeCreate, ReasonSigninRevoked, ReasonSigninRevoked},
		{"provider_detached by an attach token", EventProviderDetached, BoxCreated, PurposeAttach, ReasonNone, ReasonRPCNotAllowed},
		{"ending by a revoked member", EventEnding, BoxCreated, PurposeTeardown, ReasonSigninRevoked, ReasonNone},
		{"disconnected by a revoked member", EventDisconnected, BoxCreated, PurposeAttach, ReasonMemberNotAllowed, ReasonNone},
		{"ending out of order", EventEnding, BoxMinted, PurposeTeardown, ReasonNone, ReasonIllegalTransition},
		{"create_refused by a create token", EventCreateRefused, BoxMinted, PurposeCreate, ReasonNone, ReasonNone},
		{"create_refused by a revoked member", EventCreateRefused, BoxMinted, PurposeCreate, ReasonSigninRevoked, ReasonNone},
		{"create_refused by an attach token", EventCreateRefused, BoxMinted, PurposeAttach, ReasonNone, ReasonRPCNotAllowed},
		{"create_refused after the create", EventCreateRefused, BoxCreated, PurposeCreate, ReasonNone, ReasonIllegalTransition},
		{"unknown event", "reaped", BoxCreated, PurposeCreate, ReasonNone, ReasonIllegalTransition},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CheckEventCall(tc.ev, tc.s, tc.p, tc.f0); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}
