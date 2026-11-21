package openshellorg

import (
	"testing"
	"time"
)

// TestReapTableRows: one case per row of the reap table (lane G3).
func TestReapTableRows(t *testing.T) {
	t0 := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	base := func(s BoxState) ReapFacts {
		return ReapFacts{
			Now: t0, BoxSeen: true, BoxRunning: true, Ledger: true, State: s, StateSince: t0.Add(-time.Minute),
			MintedAt: t0.Add(-time.Minute), LastMintAt: t0.Add(-time.Minute), MaxRunMinutes: 120, MaxHoldHours: 24,
			TokenTTL: 10 * time.Minute, SyncInterval: time.Minute, CloneDeadline: 10 * time.Minute,
		}
	}
	cases := []struct {
		name   string
		f      func() ReapFacts
		rule   string
		action ReapAction
		reason EndReason
	}{
		{"unledgered", func() ReapFacts {
			f := base(BoxCreated)
			f.Ledger, f.BoxCreatedAt = false, t0.Add(-13*time.Minute)
			return f
		}, "R1-unledgered", ReapDelete, ""},
		// G3-R4: inside two intervals plus the token life (12 min here),
		// or with no known age, an unledgered box is left alone.
		{"unledgered young", func() ReapFacts {
			f := base(BoxCreated)
			f.Ledger, f.BoxCreatedAt = false, t0.Add(-11*time.Minute)
			return f
		}, "R1b-unledgered-young", ReapNone, ""},
		{"unledgered age unknown", func() ReapFacts { f := base(BoxCreated); f.Ledger = false; return f }, "R1b-unledgered-young", ReapNone, ""},
		{"settled box", func() ReapFacts { return base(BoxEnded) }, "R2-settled-box", ReapDelete, ""},
		{"settled", func() ReapFacts { f := base(BoxReaped); f.BoxSeen = false; return f }, "R3-settled", ReapNone, ""},
		{"minted box", func() ReapFacts { f := base(BoxMinted); f.MintedAt = t0.Add(-3 * time.Minute); return f }, "R4-minted-box", ReapDelete, EndNeverCreated},
		{"minted expired", func() ReapFacts {
			f := base(BoxMinted)
			f.BoxSeen, f.MintedAt = false, t0.Add(-3*time.Hour)
			return f
		}, "R5-minted-expired", ReapSettleGone, EndNeverCreated},
		{"minted", func() ReapFacts { return base(BoxMinted) }, "R6-minted", ReapNone, ""},
		{"ending gone", func() ReapFacts {
			f := base(BoxEnding)
			f.BoxSeen, f.StateSince = false, t0.Add(-time.Hour)
			return f
		}, "R7-ending-gone", ReapSettleGone, EndUnreturned},
		{"gone", func() ReapFacts { f := base(BoxHeld); f.BoxSeen = false; return f }, "R8-gone", ReapSettleGone, EndAdmin},
		{"ending wait", func() ReapFacts { f := base(BoxEnding); f.BoxSeen = false; return f }, "R9-ending-wait", ReapNone, ""},
		{"unstoppable", func() ReapFacts { f := base(BoxCollectFailed); f.UnconfirmedRestops = 3; return f }, "R10-unstoppable", ReapDeleteUnstoppable, EndDeleteUnstoppable},
		{"restop", func() ReapFacts { return base(BoxCollectFailed) }, "R11-restop", ReapRestop, ""},
		{"collect failed", func() ReapFacts { f := base(BoxCollectFailed); f.BoxRunning = false; return f }, "R12-collect-failed", ReapNone, ""},
		{"drift", func() ReapFacts { f := base(BoxCreated); f.Drift = true; return f }, "R13-drift", ReapRestoreCollectDelete, EndSpecDrift},
		{"member gone", func() ReapFacts { f := base(BoxHeld); f.MemberGone = true; return f }, "R14-member-gone", ReapCollectDelete, EndMemberRevoked},
		{"clone deadline", func() ReapFacts {
			f := base(BoxCreated)
			f.CloneStartedAt, f.HasProvider = t0.Add(-11*time.Minute), true
			return f
		}, "R15-clone-deadline", ReapCollectDelete, EndCloneDeadline},
		// G3-A4: a provider-less clone (a public repository) is never
		// reaped by the clone deadline, live or held.
		{"provider-less clone", func() ReapFacts { f := base(BoxCreated); f.CloneStartedAt = t0.Add(-11 * time.Minute); return f }, "R27-live", ReapNone, ""},
		{"provider-less clone held", func() ReapFacts {
			f := base(BoxHeld)
			f.BoxRunning, f.HeldAt, f.CloneStartedAt = false, t0, t0.Add(-11*time.Minute)
			return f
		}, "R22-held", ReapNone, ""},
		{"provider detached", func() ReapFacts {
			f := base(BoxCreated)
			f.CloneStartedAt, f.HasProvider, f.ProviderDetached = t0.Add(-11*time.Minute), true, true
			return f
		}, "R27-live", ReapNone, ""},
		{"stuck holding", func() ReapFacts { f := base(BoxHolding); f.StateSince = t0.Add(-11 * time.Minute); return f }, "R16-stuck", ReapCollectDelete, EndStuck},
		{"stuck resuming", func() ReapFacts { f := base(BoxResuming); f.StateSince = t0.Add(-11 * time.Minute); return f }, "R16-stuck", ReapCollectDelete, EndStuck},
		{"holding", func() ReapFacts { return base(BoxHolding) }, "R17-holding", ReapStop, ""},
		{"resuming", func() ReapFacts { return base(BoxResuming) }, "R18-resuming", ReapStart, ""},
		{"held running", func() ReapFacts { return base(BoxHeld) }, "R19-held-running", ReapStop, ""},
		{"held discard", func() ReapFacts {
			f := base(BoxHeld)
			f.BoxRunning, f.DiscardRequested = false, true
			return f
		}, "R20-held-discard", ReapCollectDelete, EndDiscard},
		{"held expired", func() ReapFacts {
			f := base(BoxHeld)
			f.BoxRunning, f.HeldAt, f.HoldExpiresAt = false, t0.Add(-25*time.Hour), t0.Add(time.Hour)
			return f
		}, "R21-held-expired", ReapCollectDelete, EndHoldExpired},
		{"held expiry lowered", func() ReapFacts {
			f := base(BoxHeld)
			f.BoxRunning, f.HeldAt, f.HoldExpiresAt, f.MaxHoldHours = false, t0.Add(-2*time.Hour), t0.Add(20*time.Hour), 1
			return f
		}, "R21-held-expired", ReapCollectDelete, EndHoldExpired},
		{"held", func() ReapFacts { f := base(BoxHeld); f.BoxRunning, f.HeldAt = false, t0; return f }, "R22-held", ReapNone, ""},
		{"max run", func() ReapFacts {
			f := base(BoxCreated)
			f.StateSince = t0.Add(-121 * time.Minute)
			f.LastMintAt = t0
			return f
		}, "R23-max-run", ReapCollectDelete, EndMaxRun},
		{"quiet hold", func() ReapFacts {
			f := base(BoxCreated)
			f.LastDecideAt, f.StateSince, f.HoldAllowed = t0.Add(-121*time.Second), t0.Add(-13*time.Minute), true
			return f
		}, "R24-quiet-hold", ReapHold, ""},
		{"quiet end", func() ReapFacts {
			f := base(BoxCreated)
			f.LastDecideAt, f.StateSince = t0.Add(-121*time.Second), t0.Add(-13*time.Minute)
			return f
		}, "R25-quiet-end", ReapCollectDelete, EndUnreturned},
		// G3-A5: an old mint is not quiet while the front still decides
		// (an open stream's 30 s re-check), and a created box with no
		// decide yet counts from its move to created.
		{"old mint, recent decide", func() ReapFacts {
			f := base(BoxCreated)
			f.LastMintAt, f.StateSince, f.LastDecideAt = t0.Add(-90*time.Minute), t0.Add(-90*time.Minute), t0.Add(-30*time.Second)
			return f
		}, "R27-live", ReapNone, ""},
		{"no decide yet", func() ReapFacts {
			f := base(BoxCreated)
			f.StateSince = t0.Add(-119 * time.Second)
			return f
		}, "R27-live", ReapNone, ""},
		{"ending", func() ReapFacts { f := base(BoxEnding); f.StateSince = t0.Add(-time.Hour); return f }, "R26-ending", ReapCollectDelete, EndUnreturned},
		{"ending returned", func() ReapFacts {
			f := base(BoxEnding)
			f.StateSince, f.ReturnedAt = t0.Add(-time.Hour), t0
			return f
		}, "R26-ending", ReapCollectDelete, EndReturned},
		{"live", func() ReapFacts { return base(BoxCreated) }, "R27-live", ReapNone, ""},
	}
	seen := map[string]bool{}
	for _, c := range cases {
		d := DecideReap(c.f())
		if d.Rule != c.rule || d.Action != c.action || d.Reason != c.reason {
			t.Errorf("%s: %+v, want %s %s %s", c.name, d, c.rule, c.action, c.reason)
		}
		seen[c.rule] = true
	}
	for _, r := range reapTable {
		if !seen[r.ID] {
			t.Errorf("row %s has no case", r.ID)
		}
	}
}

func TestDrainAction(t *testing.T) {
	cases := []struct {
		s      BoxState
		force  bool
		act    ReapAction
		reason EndReason
	}{
		{BoxEnded, false, ReapNone, ""},
		{BoxCollectFailed, false, ReapNone, ""},
		{BoxCollectFailed, true, ReapDeleteUnstoppable, EndDiscardWithoutCollect},
		{BoxMinted, false, ReapDelete, EndNeverCreated},
		{BoxHeld, false, ReapCollectDelete, EndDrain},
		{BoxCreated, true, ReapCollectDelete, EndDrain},
	}
	for _, c := range cases {
		if a, r := DrainAction(c.s, c.force); a != c.act || r != c.reason {
			t.Errorf("%s force=%v: %s %s", c.s, c.force, a, r)
		}
	}
}
