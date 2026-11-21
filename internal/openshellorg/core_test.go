package openshellorg

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

func TestHoldTable(t *testing.T) {
	q := DefaultQuotas()
	under := Usage{MemberLive: 1, OrgLive: 1}
	cases := []struct {
		name   string
		f      HoldFacts
		rule   string
		reason Reason
	}{
		{"policy off", HoldFacts{TriggerExplicit, HoldOff, true, q, under}, "policy-off", ReasonHoldUnavailable},
		{"H1 forced by return_to_node false", HoldFacts{TriggerEnd, HoldOnDisconnect, false, q, under}, "H1-forced", ReasonNone},
		{"H1 end policy", HoldFacts{TriggerEnd, HoldOnDisconnectAndEnd, true, q, under}, "H1-end", ReasonNone},
		{"H1 under on_disconnect", HoldFacts{TriggerEnd, HoldOnDisconnect, true, q, under}, "H1-other", ReasonHoldUnavailable},
		{"H2", HoldFacts{TriggerDisconnect, HoldOnDisconnect, true, q, under}, "H2", ReasonNone},
		{"H3", HoldFacts{TriggerExplicit, HoldOnDisconnect, true, q, under}, "H3", ReasonNone},
		{"H2 member held quota", HoldFacts{TriggerDisconnect, HoldOnDisconnect, true, q, Usage{MemberLive: 1, MemberHeld: 2}}, "H2-quota", ReasonHoldUnavailable},
		{"H2 org held quota", HoldFacts{TriggerDisconnect, HoldOnDisconnect, true, q, Usage{MemberLive: 1, OrgHeld: 40}}, "H2-quota", ReasonHoldUnavailable},
		{"invalid trigger", HoldFacts{"H9", HoldOnDisconnect, true, q, under}, "invalid", ReasonHoldUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule, r := DecideHold(tc.f)
			if rule != tc.rule || r != tc.reason {
				t.Fatalf("got %q %q, want %q %q", rule, r, tc.rule, tc.reason)
			}
		})
	}
}

func TestMoveTable(t *testing.T) {
	for _, r := range moveTable {
		if !CanMove(r.From, r.To, r.By) {
			t.Fatalf("listed move refused: %+v", r)
		}
		if !r.From.Valid() || !r.To.Valid() || r.From.Terminal() {
			t.Fatalf("bad row %+v", r)
		}
	}
	// The collect_failed exclusion (G1-R43): expiry, a member's discard, a
	// plain drain and the front never leave collect_failed.
	for _, by := range []Actor{ActorMint, ActorFront, ActorNode} {
		for _, to := range AllBoxStates() {
			if CanMove(BoxCollectFailed, to, by) {
				t.Fatalf("collect_failed left by %s to %s", by, to)
			}
		}
	}
	if CanMove(BoxCollectFailed, BoxExpired, ActorWorker) || CanMove(BoxCollectFailed, BoxHeld, ActorWorker) {
		t.Fatal("collect_failed expired or re-held")
	}
	// The front never holds a box past created, and never ends one.
	if CanMove(BoxCreated, BoxReaped, ActorFront) || CanMove(BoxHeld, BoxResuming, ActorFront) {
		t.Fatal("front move too wide")
	}
	// Terminal states have no way out.
	for _, s := range []BoxState{BoxEnded, BoxExpired, BoxReaped} {
		for _, to := range AllBoxStates() {
			for _, by := range []Actor{ActorMint, ActorFront, ActorNode, ActorWorker, ActorAdmin} {
				if CanMove(s, to, by) {
					t.Fatalf("terminal %s left", s)
				}
			}
		}
	}
}

func TestStuckAndExpiry(t *testing.T) {
	if !Stuck(BoxResuming, t0.Add(-11*time.Minute), t0) || !Stuck(BoxHolding, t0.Add(-11*time.Minute), t0) {
		t.Fatal("stuck move not seen")
	}
	if Stuck(BoxHeld, t0.Add(-time.Hour), t0) || Stuck(BoxResuming, t0.Add(-time.Minute), t0) {
		t.Fatal("false stuck")
	}
	held := t0.Add(-10 * time.Hour)
	rec := HoldExpiresAt(held, 24)
	if got := EffectiveHoldExpiry(rec, held, 24); !got.Equal(rec) {
		t.Fatal("unchanged setting moved the expiry")
	}
	if got := EffectiveHoldExpiry(rec, held, 6); !got.Equal(held.Add(6 * time.Hour)) {
		t.Fatal("a lowered max_hold_hours did not apply to a held box")
	}
	if got := EffectiveHoldExpiry(rec, held, 48); !got.Equal(rec) {
		t.Fatal("a raised max_hold_hours extended a held box")
	}
}

func TestResumeTable(t *testing.T) {
	held := liveBox()
	held.State, held.HeldAt, held.HoldExpiresAt = BoxHeld, t0.Add(-time.Hour), t0.Add(time.Hour)
	base := ResumeFacts{
		Box: held, MemberID: "m1", NewRunID: "run9", Quotas: DefaultQuotas(),
		Usage: Usage{MemberHeld: 1}, RecompiledDigest: "d1", Now: t0,
	}
	cases := []struct {
		name   string
		mut    func(f *ResumeFacts)
		action ResumeAction
		reason Reason
	}{
		{"allow", func(*ResumeFacts) {}, ResumeMove, ReasonNone},
		{"not found", func(f *ResumeFacts) { f.Box.Found = false }, "", ReasonRunNotYours},
		{"other member", func(f *ResumeFacts) { f.MemberID = "m2" }, "", ReasonRunNotYours},
		{"retry", func(f *ResumeFacts) { f.Box.State, f.Box.ActiveRunID = BoxResuming, "run9" }, ResumeReuse, ReasonNone},
		{"not held", func(f *ResumeFacts) { f.Box.State = BoxCreated }, "", ReasonRunNotHeld},
		{"collect_failed", func(f *ResumeFacts) { f.Box.State = BoxCollectFailed }, "", ReasonRunNotHeld},
		{"expired", func(f *ResumeFacts) { f.Now = t0.Add(2 * time.Hour) }, "", ReasonHoldExpired},
		{"expired by lowered setting", func(f *ResumeFacts) { f.Quotas.MaxHoldHours = 1 }, "", ReasonHoldExpired},
		{"concurrent", func(f *ResumeFacts) { f.Usage.MemberLive = 2 }, "", ReasonQuotaConcurrent},
		{"org concurrent", func(f *ResumeFacts) { f.Usage.OrgLive = 20 }, "", ReasonQuotaOrgConcurrent},
		{"boxes", func(f *ResumeFacts) { f.Usage.MemberLive, f.Usage.MemberHeld = 1, 3 }, "", ReasonQuotaBoxes},
		{"spec changed", func(f *ResumeFacts) { f.RecompiledDigest = "d2" }, "", ReasonSpecChangedSinceHold},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := base
			tc.mut(&f)
			a, r := CheckResume(f)
			if a != tc.action || r != tc.reason {
				t.Fatalf("got %q %q", a, r)
			}
		})
	}
}

func TestEndedRuleE1(t *testing.T) {
	q := DefaultQuotas()
	u := Usage{MemberLive: 1, OrgLive: 1}
	minted := liveBox()
	minted.ReturnMintedAt = t0
	withheld := liveBox()
	withheld.ReturnToNode = false
	off := liveBox()
	off.HoldPolicy = HoldOff
	offWithheld := withheld
	offWithheld.HoldPolicy = HoldOff
	andEnd := liveBox()
	andEnd.HoldPolicy = HoldOnDisconnectAndEnd
	ending := liveBox()
	ending.State = BoxEnding
	cases := []struct {
		name    string
		rep     EndedReport
		box     BoxFacts
		u       Usage
		outcome EndedOutcome
		reason  Reason
	}{
		{"returned after a return token", EndedReport{Returned: true}, minted, u, EndedReturned, ReasonNone},
		{"returned forged under false", EndedReport{Returned: true}, withheld, u, EndedRefused, ReasonReturnWithheld},
		{"returned without a return token", EndedReport{Returned: true}, liveBox(), u, EndedRefused, ReasonReturnNotTaken},
		{"hold on_disconnect_and_end", EndedReport{Hold: true}, andEnd, u, EndedHold, ReasonNone},
		{"hold under on_disconnect", EndedReport{Hold: true}, liveBox(), u, EndedUnreturned, ReasonHoldUnavailable},
		{"hold with policy off", EndedReport{Hold: true}, off, u, EndedUnreturned, ReasonHoldUnavailable},
		// FX3 item 9: a cut stream's hold is a disconnect (H2), which
		// on_disconnect allows; holding off still refuses it.
		{"cut stream held under on_disconnect", EndedReport{Hold: true, Disconnected: true}, liveBox(), u, EndedHold, ReasonNone},
		{"cut stream with policy off", EndedReport{Hold: true, Disconnected: true}, off, u, EndedUnreturned, ReasonHoldUnavailable},
		{"disconnected without hold is a plain end", EndedReport{Disconnected: true}, liveBox(), u, EndedUnreturned, ReasonNone},
		// FX3-A3: a disconnect holds only a live box within max_run_minutes.
		{"cut within max_run still held", EndedReport{Hold: true, Disconnected: true, Now: t0.Add(time.Hour)}, createdAt(liveBox(), t0), u, EndedHold, ReasonNone},
		{"cut past max_run not held", EndedReport{Hold: true, Disconnected: true, Now: t0.Add(3 * time.Hour)}, createdAt(liveBox(), t0), u, EndedUnreturned, ReasonHoldUnavailable},
		{"cut of a box no longer live not held", EndedReport{Hold: true, Disconnected: true, Now: t0}, ending, u, EndedUnreturned, ReasonHoldUnavailable},
		{"hold over quota", EndedReport{Hold: true}, andEnd, Usage{MemberLive: 1, MemberHeld: 2}, EndedUnreturned, ReasonHoldUnavailable},
		{"forced hold under return_to_node false", EndedReport{}, withheld, u, EndedHold, ReasonNone},
		{"forced hold impossible: collect", EndedReport{}, offWithheld, u, EndedUnreturned, ReasonNone},
		{"plain end without return", EndedReport{}, liveBox(), u, EndedUnreturned, ReasonNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, r := JudgeEnded(tc.rep, tc.box, q, tc.u)
			if o != tc.outcome || r != tc.reason {
				t.Fatalf("got %q %q, want %q %q", o, r, tc.outcome, tc.reason)
			}
		})
	}
}

func TestDiscardTable(t *testing.T) {
	held := liveBox()
	held.State = BoxHeld
	failed := liveBox()
	failed.State = BoxCollectFailed
	cases := []struct {
		name   string
		f      DiscardFacts
		action DiscardAction
		reason Reason
	}{
		{"member discards held", DiscardFacts{Box: held, MemberID: "m1"}, DiscardCollectThenDelete, ReasonNone},
		{"other member", DiscardFacts{Box: held, MemberID: "m2"}, "", ReasonRunNotYours},
		{"member on collect_failed", DiscardFacts{Box: failed, MemberID: "m1"}, "", ReasonCollectFailedOnly},
		{"admin plain on collect_failed", DiscardFacts{Box: failed, ByAdmin: true}, "", ReasonCollectFailedOnly},
		{"admin without collect", DiscardFacts{Box: failed, ByAdmin: true, WithoutCollect: true}, DiscardDeleteNow, ReasonNone},
		{"live box", DiscardFacts{Box: liveBox(), MemberID: "m1"}, "", ReasonRunNotHeld},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, r := DecideDiscard(tc.f)
			if a != tc.action || r != tc.reason {
				t.Fatalf("got %q %q", a, r)
			}
		})
	}
}

func TestDeviceTable(t *testing.T) {
	exp := t0.Add(DeviceCodeTTL)
	for _, row := range deviceTable {
		to, r := DeviceStep(row.From, row.Event, exp, t0)
		if to != row.To || r != row.Reason {
			t.Fatalf("row %+v: got %s %s", row, to, r)
		}
	}
	if to, r := DeviceStep(DevicePending, DeviceApprove, exp, exp); to != DeviceExpired || r != ReasonDeviceCodeExpired {
		t.Fatalf("approve after expiry: %s %s", to, r)
	}
	if to, r := DeviceStep(DeviceApproved, DevicePoll, exp, exp.Add(time.Second)); to != DeviceExpired || r != ReasonDeviceCodeExpired {
		t.Fatalf("poll after expiry: %s %s", to, r)
	}
	if to, r := DeviceStep(DevicePending, "nope", exp, t0); to != DevicePending || r != ReasonIllegalTransition {
		t.Fatalf("unknown event: %s %s", to, r)
	}
}

func TestUserCode(t *testing.T) {
	c, err := NewUserCode(bytes.NewReader(bytes.Repeat([]byte{7}, 8)))
	if err != nil || len(c) != 9 || c[4] != '-' {
		t.Fatalf("code %q %v", c, err)
	}
	for in, want := range map[string]string{
		strings.ToLower(c): c, strings.ReplaceAll(c, "-", " "): c, "BCDF-GHJA": "", "BCD": "", "": "",
	} {
		if got := NormalizeUserCode(in); got != want {
			t.Fatalf("NormalizeUserCode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGrantRules(t *testing.T) {
	g := GrantFacts{Found: true, MemberID: "m", ExpiresAt: t0.Add(time.Hour), AgentKeyFP: "f", SessionGen: 1, AuthEpoch: 1}
	m := MemberNow{ID: "m", AgentKeyFP: "f", SessionGen: 1, AuthEpoch: 1}
	if rule, r := CheckGrant(g, m, t0); rule != "" || r != ReasonNone {
		t.Fatalf("good grant: %s %s", rule, r)
	}
	g2 := g
	g2.AgentKeyFP = ""
	if _, r := CheckGrant(g2, m, t0); r != ReasonSigninRevoked {
		t.Fatal("a grant without a key binding passed")
	}
	for in, want := range map[time.Duration]time.Duration{0: 12 * time.Hour, time.Minute: time.Hour, 100 * time.Hour: 72 * time.Hour, 5 * time.Hour: 5 * time.Hour} {
		if got := ClampGrantTTL(in); got != want {
			t.Fatalf("ClampGrantTTL(%v) = %v", in, got)
		}
	}
	s, h, err := NewSecret(bytes.NewReader(make([]byte, 64)), HandleBytes)
	if err != nil || len(s) != 43 || h != HashSecret(s) || len(h) != 64 {
		t.Fatalf("secret %q %q %v", s, h, err)
	}
	if _, _, err := NewSecret(bytes.NewReader(nil), 4); err == nil {
		t.Fatal("short reader accepted")
	}
}

func TestQuotaReserveSettle(t *testing.T) {
	q := DefaultQuotas()
	r := Reserve(q)
	if r.Counted() != 120 {
		t.Fatalf("reserve counts %d", r.Counted())
	}
	r = Settle(r, 30)
	if r.Counted() != 30 || Settle(r, 90).Counted() != 30 {
		t.Fatal("settle wrong or not idempotent")
	}
	if Settle(Reserve(q), 500).Counted() != 120 || Settle(Reserve(q), -5).Counted() != 0 {
		t.Fatal("settle not clamped")
	}
	if CheckCreateQuota(q, Usage{}) != ReasonNone || CheckHoldQuota(q, Usage{MemberLive: 1}) != ReasonNone {
		t.Fatal("empty usage refused")
	}
}

func TestClaimsProfiles(t *testing.T) {
	c := RunTokenClaims(RunTokenParams{
		Issuer: "https://o/sandbox-idp", GatewayID: "gw", MemberID: "m1",
		Purpose: PurposeCreate, RunID: "r1", SpecHash: "d", Jti: "j", Now: t0,
	})
	if c.Aud != "openshell-front:gw" || c.SboBox != "r1" || c.SboSpec != "d" || c.Exp-c.Iat != 600 || len(c.Roles) != 0 {
		t.Fatalf("run claims %+v", c)
	}
	if p, r := CheckRunClaims(c, "https://o/sandbox-idp", "gw", t0.Add(time.Minute)); p != PurposeCreate || r != ReasonNone {
		t.Fatalf("check %s %s", p, r)
	}
	if _, r := CheckRunClaims(c, "https://o/sandbox-idp", "gw", t0.Add(11*time.Minute)); r != ReasonRunTokenInvalid {
		t.Fatal("expired run token passed")
	}
	mg := MemberGatewayClaims("https://o/sandbox-idp", "gw", "m1", "j2", t0)
	if mg.Aud != "openshell:gw" || len(mg.Roles) != 1 || mg.Roles[0] != RoleUser || mg.Exp-mg.Iat != 60 {
		t.Fatalf("member claims %+v", mg)
	}
	// A gateway token never passes as a run token (audience and roles).
	if _, r := CheckRunClaims(mg, "https://o/sandbox-idp", "gw", t0); r != ReasonRunTokenInvalid {
		t.Fatal("member gateway token accepted as run token")
	}
	ad := SyncAdminClaims("https://o/sandbox-idp", "gw", "j3", t0)
	if ad.Roles[0] != RoleAdmin || ad.Exp-ad.Iat != 300 || ad.Sub != SubjectAdmin {
		t.Fatalf("admin claims %+v", ad)
	}
	at := RunTokenClaims(RunTokenParams{GatewayID: "gw", MemberID: "m", Purpose: PurposeAttach, RunID: "r2", BoxRunID: "r1", SpecHash: "x", Now: t0, TTL: 99 * time.Hour})
	if at.SboSpec != "" || at.SboBox != "r1" || at.Exp-at.Iat != 3600 {
		t.Fatalf("attach claims %+v", at)
	}
}

func TestProofMessages(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(bytes.NewReader(make([]byte, 64)))
	body := []byte(`{"run_id":"r1"}`)
	msg := NodeMessage(DomainMint, "org", "r1", "create", t0.Unix(), body)
	sig := ed25519.Sign(priv, msg)
	if !VerifyProof(pub, msg, sig) {
		t.Fatal("good proof refused")
	}
	for _, other := range [][]byte{
		NodeMessage(DomainFetch, "org", "r1", "create", t0.Unix(), body),
		NodeMessage(DomainMint, "org2", "r1", "create", t0.Unix(), body),
		NodeMessage(DomainMint, "org", "r1", "attach", t0.Unix(), body),
		NodeMessage(DomainMint, "org", "r1", "create", t0.Unix()+1, body),
		NodeMessage(DomainMint, "org", "r1", "create", t0.Unix(), []byte(`{}`)),
		FrontMessage("POST", "/internal/openshell/v1/decide", "rep", t0.Unix(), body),
	} {
		if VerifyProof(pub, other, sig) {
			t.Fatalf("proof verified on another message %q", other)
		}
	}
	if VerifyProof(pub[:5], msg, sig) || VerifyProof(pub, msg, sig[:3]) {
		t.Fatal("malformed key or signature accepted")
	}
	if !Fresh(t0.Unix()-120, t0) || Fresh(t0.Unix()-121, t0) || Fresh(t0.Unix()+121, t0) {
		t.Fatal("window wrong")
	}
	var c ReplayCache
	k := ReplayKey("org", "m1", "n1", "r1", "create", t0.Unix(), []byte("{}"))
	for _, other := range []string{
		ReplayKey("org", "m2", "n1", "r1", "create", t0.Unix(), []byte("{}")),
		ReplayKey("org", "m1", "n2", "r1", "create", t0.Unix(), []byte("{}")),
		ReplayKey("org2", "m1", "n1", "r1", "create", t0.Unix(), []byte("{}")),
		ReplayKey("org", "m1", "n1", "r1", "create", t0.Unix(), []byte(`{"x":1}`)),
	} {
		if other == k {
			t.Fatal("replay keys of different callers or bodies collide")
		}
	}
	if c.Seen(k, t0.Unix(), t0) || !c.Seen(k, t0.Unix(), t0) {
		t.Fatal("replay not caught")
	}
	if c.Seen(k, t0.Unix(), t0.Add(5*time.Minute)) {
		t.Fatal("old entry not dropped")
	}
	for in, want := range map[string]bool{"r1": true, "": false, "a|b": false, "a b": false, strings.Repeat("x", 129): false} {
		if SafeID(in) != want {
			t.Fatalf("SafeID(%q)", in)
		}
	}
}

func TestNames(t *testing.T) {
	b := BoxName("org", "run")
	if len(b) != BoxNameLen || !IsBoxName(b) || b == BoxName("org", "run2") || b == BoxName("org2", "run") {
		t.Fatalf("box name %q", b)
	}
	p := ProviderInstanceName(b)
	if !IsProviderInstanceName(p) || IsBoxName(p) || len(p) != 20 {
		t.Fatalf("provider name %q", p)
	}
	w := WorkspaceName("m1")
	if !IsMemberWorkspace(w) || IsMemberWorkspace(AdminWorkspace) || w == WorkspaceName("m2") || strings.Contains(w, "m1") {
		t.Fatalf("workspace %q", w)
	}
	for in, want := range map[string]bool{"gw-1": true, "": false, "GW": false, strings.Repeat("a", 33): false} {
		if GatewayIDValid(in) != want {
			t.Fatalf("GatewayIDValid(%q)", in)
		}
	}
	for in, want := range map[string]string{
		"https://GitHub.com/Org/Repo.git/": "https://github.com/Org/Repo",
		"git@github.com:Org/Repo.git":      "ssh://git@github.com/Org/Repo",
		"ssh://git@Host.example/a/b":       "ssh://git@host.example/a/b",
		"http://github.com/a/b":            "",
		"file:///tmp/x":                    "",
		"https://github.com":               "",
	} {
		if got := NormalizeRepository(in); got != want {
			t.Fatalf("NormalizeRepository(%q) = %q, want %q", in, got, want)
		}
	}
	if GitRowID("https://github.com/a/b.git") != GitRowID("https://GITHUB.com/a/b") || len(GitRowID("https://x/y")) != 16 {
		t.Fatal("row id not stable")
	}
	if !strings.HasPrefix(GitSecretName("https://x/y"), "openshell-git-") || !strings.HasPrefix(RequestID("o", "r"), "obsr-") {
		t.Fatal("names")
	}
}

func TestClosedSets(t *testing.T) {
	seen := map[Reason]bool{}
	for _, r := range AllReasons() {
		if seen[r] || !r.Valid() {
			t.Fatalf("reason %q duplicated or invalid", r)
		}
		seen[r] = true
	}
	if ReasonNone.Valid() || Reason("x").Valid() {
		t.Fatal("open reason accepted")
	}
	if len(AllCollectFailReasons()) != 7 || len(AllEndReasons()) < 10 || len(AllPurposes()) != 6 {
		t.Fatal("closed sets changed")
	}
}

func TestCompileTable(t *testing.T) {
	q := DefaultQuotas()
	in := CompileInput{
		OrgID: "org-1", RunID: "AAAAAAAAAAAAAAAAAAAAAA", MemberID: "m1", NodeHash: "n1",
		Image: "registry.example.com/box@sha256:" + strings.Repeat("a", 64), Quotas: q,
		Narrowed: Narrowed{Tier: TierProxyOnly, Source: SourceCloneLocal},
	}
	cases := []struct {
		tier   Tier
		reason Reason
	}{{TierNone, ReasonNone}, {TierProxyOnly, ReasonNone}, {TierInternet, ReasonBlockedCIDRsMissing}, {"host", ReasonInputWidensOrg}}
	for _, tc := range cases {
		t.Run(string(tc.tier), func(t *testing.T) {
			c := in
			c.Narrowed.Tier = tc.tier
			spec, d, r, err := CompileOrgSpec(c)
			if err != nil || r != tc.reason {
				t.Fatalf("reason %s err %v", r, err)
			}
			if r != ReasonNone {
				return
			}
			if spec.TTY || spec.Image != c.Image || spec.BoxName != BoxName("org-1", c.RunID) || spec.Workspace != WorkspaceName("m1") ||
				len(d) != 64 || spec.CPU != 2 || spec.MemoryMiB != 4096 || strings.Join(spec.Command, " ") != "sh -c exec sleep infinity" {
				t.Fatalf("spec %+v", spec)
			}
			if !strings.Contains(spec.PolicyYAML, "version: 1") || strings.Contains(spec.PolicyYAML, "network_policies:\n  -") {
				t.Fatalf("policy %s", spec.PolicyYAML)
			}
			for _, l := range spec.Labels {
				if strings.Contains(l.Value, "m1") || strings.Contains(l.Value, "org-1") {
					t.Fatalf("label %v carries a raw id", l)
				}
			}
			// The recompile at resume, from another node, matches; a
			// changed image or quota does not.
			c2 := c
			c2.NodeHash = "n2"
			got, r2, _ := RecompileForResumeWith(spec, CompileInput{OrgID: "org-1", RunID: c.RunID, MemberID: "m1", Image: c.Image, Quotas: q, Narrowed: c.Narrowed})
			if r2 != ReasonNone || got != d {
				t.Fatalf("resume digest %s != %s", got, d)
			}
			q2 := q
			q2.BoxCPU = 4
			if got, _, _ := RecompileForResumeWith(spec, CompileInput{OrgID: "org-1", RunID: c.RunID, MemberID: "m1", Image: c.Image, Quotas: q2, Narrowed: c.Narrowed}); got == d {
				t.Fatal("a changed resource kept the digest")
			}
		})
	}
	bad := in
	bad.RunID = "x"
	if _, _, _, err := CompileOrgSpec(bad); err == nil {
		t.Fatal("an unencodable run id compiled")
	}
}

// createdAt is b created at t.
func createdAt(b BoxFacts, t time.Time) BoxFacts {
	b.CreatedAt = t
	return b
}
