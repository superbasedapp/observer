package openshellorg

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)

// goodFacts is a create mint every rule allows.
func goodFacts() MintFacts {
	return MintFacts{
		ProofOK: true, Enabled: true, Compiled: true, Drain: DrainActive, Managed: true,
		Grant: GrantFacts{
			Found: true, ID: "g1", MemberID: "m1", ExpiresAt: t0.Add(time.Hour),
			AgentKeyFP: "fp1", SessionGen: 3, AuthEpoch: 5,
		},
		Member:  MemberNow{ID: "m1", Active: true, Allowed: true, AgentKeyFP: "fp1", SessionGen: 3, AuthEpoch: 5},
		NodeID:  "n1",
		Request: MintRequest{RunID: "run1", Purpose: PurposeCreate, Tier: TierProxyOnly, Source: SourceCloneLocal, LaptopRelay: true},
		Org: OrgValues{
			Tiers: []Tier{TierNone, TierProxyOnly, TierInternet}, LaptopRelay: LaptopRelayAllowed,
			HoldPolicy: HoldOnDisconnect, ReturnToNode: true, AllowRemoteClone: true,
			RemoteAllowedHosts: []string{"git.example.com"}, BlockedCIDRs: []string{"10.0.0.0/8"},
			HostAddrs: []string{"10.0.0.1"}, HostAddrsKnown: true,
			EgressAllowHosts: []string{"pypi.org", "git.example.com"},
			GitProviders:     []GitProviderRow{{Repository: "https://git.example.com/org/repo.git", ProviderProfile: "p", AllowedTeams: []string{"t1"}}},
		},
		MemberTeams: []string{"t1"},
		Quotas:      DefaultQuotas(),
		Sync:        SyncFacts{Present: true, Sound: true, CheckedAt: t0.Add(-time.Minute), Interval: time.Minute},
		Now:         t0,
	}
}

func liveBox() BoxFacts {
	return BoxFacts{
		Found: true, RunID: "run1", ActiveRunID: "run1", MemberID: "m1", NodeID: "n1",
		State: BoxCreated, SpecDigest: "d1", ReturnToNode: true, HoldPolicy: HoldOnDisconnect,
	}
}

func TestMintTable(t *testing.T) {
	cases := []struct {
		name   string
		mut    func(f *MintFacts)
		rule   string
		reason Reason
		action MintAction
	}{
		{"allow create reserves", func(*MintFacts) {}, "", ReasonNone, MintActionReserve},
		{"T0 bad proof", func(f *MintFacts) { f.ProofOK = false }, "T0", ReasonProofInvalid, ""},
		{"T0 replayed shape purpose", func(f *MintFacts) { f.Request.Purpose = "bogus" }, "T0", ReasonProofInvalid, ""},
		{"T0 unsafe run id", func(f *MintFacts) { f.Request.RunID = "a\nb" }, "T0", ReasonProofInvalid, ""},
		{"T1 disabled", func(f *MintFacts) { f.Enabled = false }, "T1", ReasonOff, ""},
		{"T1 not compiled", func(f *MintFacts) { f.Compiled = false }, "T1", ReasonOff, ""},
		{"T1 draining", func(f *MintFacts) { f.Drain = DrainDraining }, "T1", ReasonDraining, ""},
		{"T2 individual", func(f *MintFacts) { f.Managed = false }, "T2", ReasonNodeNotManaged, ""},
		{"T3 no grant", func(f *MintFacts) { f.Grant.Found = false }, "T3-T4", ReasonSigninRequired, ""},
		{"T3 expired", func(f *MintFacts) { f.Grant.ExpiresAt = t0 }, "T3-T4", ReasonSigninExpired, ""},
		{"T3 revoked", func(f *MintFacts) { f.Grant.RevokedAt = t0 }, "T3-T4", ReasonSigninRevoked, ""},
		{"T3 other member", func(f *MintFacts) { f.Grant.MemberID = "m2" }, "T3-T4", ReasonSigninRequired, ""},
		{"T3 re-keyed", func(f *MintFacts) { f.Member.AgentKeyFP = "fp2" }, "T3-T4", ReasonSigninRevoked, ""},
		{"T4 session generation", func(f *MintFacts) { f.Member.SessionGen = 4 }, "T3-T4", ReasonSigninRevoked, ""},
		{"T4 auth epoch", func(f *MintFacts) { f.Member.AuthEpoch = 6 }, "T3-T4", ReasonSigninRevoked, ""},
		{"T5 inactive", func(f *MintFacts) { f.Member.Active = false }, "T5", ReasonMemberNotAllowed, ""},
		{"T5 not allowed", func(f *MintFacts) { f.Member.Allowed = false }, "T5", ReasonMemberNotAllowed, ""},
		{"T5b tier outside org", func(f *MintFacts) { f.Org.Tiers = []Tier{TierNone} }, "T5b", ReasonInputWidensOrg, ""},
		{"T5b live source", func(f *MintFacts) { f.Request.Source = "live" }, "T5b", ReasonInputWidensOrg, ""},
		{"T5b remote clone off", func(f *MintFacts) {
			f.Request.Source = SourceCloneRemote
			f.Org.AllowRemoteClone = false
		}, "T5b", ReasonInputWidensOrg, ""},
		{"T5b clone url on clone-local", func(f *MintFacts) { f.Request.CloneURL = "https://git.example.com/x" }, "T5b", ReasonInputWidensOrg, ""},
		{"T5b internet without blocked cidrs", func(f *MintFacts) {
			f.Request.Tier = TierInternet
			f.Org.BlockedCIDRs = nil
		}, "T5b", ReasonBlockedCIDRsMissing, ""},
		{"T5b internet with a CIDR host entry", func(f *MintFacts) {
			f.Request.Tier = TierInternet
			f.Org.HostAddrs = []string{"10.0.0.1", "10.0.0.1/32"}
		}, "T5b", ReasonHostAddrsInvalid, ""},
		{"T5b internet with host addresses", func(f *MintFacts) {
			f.Request.Tier = TierInternet
			f.Org.HostAddrs = []string{"10.0.0.1"}
		}, "", ReasonNone, MintActionReserve},
		{"T5b internet with the host list not known", func(f *MintFacts) {
			f.Request.Tier = TierInternet
			f.Org.HostAddrs, f.Org.HostAddrsKnown = nil, false
		}, "T5b", ReasonGatewayStateStale, ""},
		{"T5b internet with no host addresses listed", func(f *MintFacts) {
			f.Request.Tier = TierInternet
			f.Org.HostAddrs = nil
		}, "T5b", ReasonHostAddrsMissing, ""},
		{"T5b resume internet with no host addresses listed", func(f *MintFacts) {
			f.Request.Tier, f.Request.Purpose = TierInternet, PurposeResume
			f.Org.HostAddrs = nil
		}, "T5b", ReasonHostAddrsMissing, ""},
		{"T5b proxy_only never reads host entries", func(f *MintFacts) {
			f.Org.HostAddrs = []string{"10.0.0.1/32"}
		}, "", ReasonNone, MintActionReserve},
		{"T5b clone needs egress", func(f *MintFacts) {
			f.Request.Source = SourceCloneRemote
			f.Request.CloneURL = "https://git.example.com/org/repo"
		}, "T5b", ReasonRemoteCloneNeedsEgress, ""},
		{"T5b clone hosts missing", func(f *MintFacts) {
			f.Request.Tier, f.Request.Source = TierInternet, SourceCloneRemote
			f.Org.RemoteAllowedHosts = nil
		}, "T5b", ReasonRemoteCloneHostsMissing, ""},
		{"T5b clone hosts disjoint", func(f *MintFacts) {
			f.Request.Tier, f.Request.Source = TierInternet, SourceCloneRemote
			f.Request.NodeRemoteAllowedHosts = []string{"other.example.com"}
		}, "T5b", ReasonRemoteCloneHostsDisjoint, ""},
		{"T5b clone url ext", func(f *MintFacts) {
			f.Request.Tier, f.Request.Source = TierInternet, SourceCloneRemote
			f.Request.CloneURL = "ext::sh -c id"
		}, "T5b", ReasonCloneURLInvalid, ""},
		{"T5b clone url other host", func(f *MintFacts) {
			f.Request.Tier, f.Request.Source = TierInternet, SourceCloneRemote
			f.Request.CloneURL = "https://evil.example.com/org/repo"
		}, "T5b", ReasonCloneURLInvalid, ""},
		{"T5b confused deputy", func(f *MintFacts) {
			f.Request.Tier, f.Request.Source = TierInternet, SourceCloneRemote
			f.Request.CloneURL = "https://GIT.example.com/org/repo"
			f.MemberTeams = []string{"t9"}
		}, "T5b", ReasonCloneRepositoryNotAllowed, ""},
		{"T6 idempotent retry", func(f *MintFacts) {
			f.Box = liveBox()
			f.Box.State = BoxMinted
		}, "", ReasonNone, MintActionReuse},
		{"T6 run exists", func(f *MintFacts) { f.Box = liveBox() }, "T6", ReasonRunExists, ""},
		{"T6 other member's run", func(f *MintFacts) { f.Box = liveBox(); f.Box.MemberID = "m2" }, "T6", ReasonRunNotYours, ""},
		{"T6 member concurrent", func(f *MintFacts) { f.Usage.MemberLive = 2 }, "T6", ReasonQuotaConcurrent, ""},
		{"T6 org concurrent", func(f *MintFacts) { f.Usage.OrgLive = 20 }, "T6", ReasonQuotaOrgConcurrent, ""},
		{"T6 boxes", func(f *MintFacts) { f.Usage.MemberLive, f.Usage.MemberHeld = 1, 2 }, "T6", ReasonQuotaBoxes, ""},
		{"T6 daily minutes", func(f *MintFacts) { f.Usage.MemberMinutesToday = 400 }, "T6", ReasonQuotaDailyMinutes, ""},
		{"T7 attach allowed", func(f *MintFacts) { f.Request.Purpose = PurposeAttach; f.Box = liveBox() }, "", ReasonNone, MintActionToken},
		{"T7 unknown", func(f *MintFacts) { f.Request.Purpose = PurposeAttach }, "T7", ReasonRunUnknown, ""},
		{"T7 reaped", func(f *MintFacts) {
			f.Request.Purpose, f.Box = PurposeAttach, liveBox()
			f.Box.State = BoxReaped
		}, "T7", ReasonRunUnknown, ""},
		{"T7 other node", func(f *MintFacts) {
			f.Request.Purpose, f.Box = PurposeAttach, liveBox()
			f.Box.NodeID = "n2"
		}, "T7", ReasonRunNotYours, ""},
		{"T7 superseded run", func(f *MintFacts) {
			f.Request.Purpose, f.Box = PurposeAttach, liveBox()
			f.Box.ActiveRunID = "run2"
		}, "T7", ReasonRunNotYours, ""},
		{"T7 held", func(f *MintFacts) {
			f.Request.Purpose, f.Box = PurposeAttach, liveBox()
			f.Box.State = BoxHeld
		}, "T7", ReasonRunHeld, ""},
		{"T7x return allowed", func(f *MintFacts) { f.Request.Purpose, f.Box = PurposeReturn, liveBox() }, "", ReasonNone, MintActionRecordReturn},
		{"T7x return withheld", func(f *MintFacts) {
			f.Request.Purpose, f.Box = PurposeReturn, liveBox()
			f.Box.ReturnToNode = false
		}, "T7x", ReasonReturnWithheld, ""},
		{"T7x teardown needs collect", func(f *MintFacts) {
			f.Request.Purpose, f.Box = PurposeTeardown, liveBox()
			f.Box.ReturnToNode = false
		}, "T7x", ReasonTeardownNeedsCollect, ""},
		{"T7x teardown after return", func(f *MintFacts) {
			f.Request.Purpose, f.Box = PurposeTeardown, liveBox()
			f.Box.ReturnToNode, f.Box.ReturnedAt = false, t0
		}, "", ReasonNone, MintActionToken},
		{"T7r resume", func(f *MintFacts) {
			f.Request.Purpose, f.Request.RunID, f.Box = PurposeResume, "run9", liveBox()
			f.Box.State, f.Box.HeldAt, f.Box.HoldExpiresAt = BoxHeld, t0.Add(-time.Hour), t0.Add(time.Hour)
			f.RecompiledDigest = "d1"
		}, "", ReasonNone, MintActionResume},
		{"T7r spec changed", func(f *MintFacts) {
			f.Request.Purpose, f.Request.RunID, f.Box = PurposeResume, "run9", liveBox()
			f.Box.State, f.Box.HeldAt, f.Box.HoldExpiresAt = BoxHeld, t0.Add(-time.Hour), t0.Add(time.Hour)
			f.RecompiledDigest = "d2"
		}, "T7r", ReasonSpecChangedSinceHold, ""},
		{"T7h forbidden", func(f *MintFacts) { f.Org.LaptopRelay = LaptopRelayForbidden }, "T7h", ReasonLaptopRelayForbidden, ""},
		{"T7h not opted in", func(f *MintFacts) { f.Request.LaptopRelay = false }, "T7h", ReasonLaptopRelayNotOptedIn, ""},
		{"T8 no sync yet", func(f *MintFacts) { f.Sync = SyncFacts{} }, "T8", ReasonGatewayStateStale, ""},
		{"T8 stale", func(f *MintFacts) { f.Sync.CheckedAt = t0.Add(-4 * time.Minute) }, "T8", ReasonGatewayStateStale, ""},
		{"T8 unsound", func(f *MintFacts) { f.Sync.Sound = false }, "T8", ReasonGatewayUnsound, ""},
		{"probe skips T5b to T7r", func(f *MintFacts) { f.Request.Purpose, f.Request.Tier = PurposeProbe, "bogus" }, "", ReasonNone, MintActionToken},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := goodFacts()
			tc.mut(&f)
			d := DecideMint(f)
			if d.Reason != tc.reason || d.Rule != tc.rule {
				t.Fatalf("got rule %q reason %q, want %q %q", d.Rule, d.Reason, tc.rule, tc.reason)
			}
			if d.Allow != (tc.reason == ReasonNone) {
				t.Fatalf("allow = %v", d.Allow)
			}
			if tc.action != "" && d.Action != tc.action {
				t.Fatalf("action = %q, want %q", d.Action, tc.action)
			}
			if !d.Allow && !d.Reason.Valid() {
				t.Fatalf("reason %q is not in the closed set", d.Reason)
			}
		})
	}
}

func TestMintNarrowsCloneInputs(t *testing.T) {
	f := goodFacts()
	f.Request.Tier, f.Request.Source = TierInternet, SourceCloneRemote
	f.Request.CloneURL = "https://git.example.com/org/repo"
	f.Request.NodeEgressAllowHosts = []string{"PyPI.org", "evil.example.com"}
	d := DecideMint(f)
	if !d.Allow {
		t.Fatalf("refused: %s %s", d.Rule, d.Reason)
	}
	if len(d.Inputs.EgressHosts) != 1 || d.Inputs.EgressHosts[0] != "pypi.org" {
		t.Fatalf("egress hosts not narrowed: %v", d.Inputs.EgressHosts)
	}
	if d.Inputs.GitProvider == nil || d.Inputs.GitProvider.ProviderProfile != "p" {
		t.Fatalf("git provider row not chosen: %+v", d.Inputs.GitProvider)
	}
	// A repository with no git_providers row clones without a credential.
	f.Request.CloneURL = "https://git.example.com/org/public"
	if d := DecideMint(f); !d.Allow || d.Inputs.GitProvider != nil {
		t.Fatalf("public repository: %+v", d)
	}
}

func TestMintRuleOrder(t *testing.T) {
	want := []string{"T0", "T1", "T2", "T3-T4", "T5", "T5b", "T6", "T7", "T7x", "T7r", "T7h", "T8"}
	got := MintRuleIDs()
	if len(got) != len(want) {
		t.Fatalf("rules %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rule %d = %s, want %s", i, got[i], want[i])
		}
	}
}
