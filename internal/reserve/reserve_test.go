package reserve

import (
	"errors"
	"math"
	"sync"
	"testing"
	"time"
)

// TestCheckRules is one row per limitRules row, plus the no-match rows.
func TestCheckRules(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		l        Limit
		breached bool
		rule     string
	}{
		{name: "invalid: NaN cap fails closed", l: Limit{Cap: math.NaN(), Estimate: 1}, breached: true, rule: RuleInvalid},
		{name: "invalid: infinite committed fails closed", l: Limit{Cap: 10, Committed: math.Inf(1)}, breached: true, rule: RuleInvalid},
		{name: "invalid: negative estimate fails closed", l: Limit{Cap: 10, Estimate: -1}, breached: true, rule: RuleInvalid},
		{name: "invalid: negative committed fails closed", l: Limit{Cap: 10, Committed: -5, Estimate: 1}, breached: true, rule: RuleInvalid},
		{name: "at_cap: committed reached the ceiling", l: Limit{Cap: 5, Committed: 5, Boundary: AtCap}, breached: true, rule: RuleAtCap},
		{name: "at_cap: committed past the ceiling", l: Limit{Cap: 5, Committed: 5.2, Boundary: AtCap}, breached: true, rule: RuleAtCap},
		{name: "at_cap: just below the ceiling admits", l: Limit{Cap: 5, Committed: 4.999, Boundary: AtCap}},
		{name: "over_cap: one past the cap", l: Limit{Cap: 100, Committed: 100, Estimate: 1}, breached: true, rule: RuleOverCap},
		{name: "over_cap: exactly at the cap admits", l: Limit{Cap: 100, Committed: 99, Estimate: 1}},
		{name: "over_cap: zero cap refuses a unit", l: Limit{Cap: 0, Estimate: 1}, breached: true, rule: RuleOverCap},
		{name: "over_cap: worst case past a USD cap", l: Limit{Unit: UnitUSD, Cap: 1, Committed: 0.6, Estimate: 0.5}, breached: true, rule: RuleOverCap},
		{name: "over_cap: zero estimate under a full cap admits", l: Limit{Cap: 1, Committed: 1}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			b, breached := Check(c.l)
			if breached != c.breached || b.Rule != c.rule {
				t.Fatalf("Check = (%+v, %v), want breached=%v rule=%q", b, breached, c.breached, c.rule)
			}
		})
	}
}

// TestBreachArithmetic pins Remaining and Ratio.
func TestBreachArithmetic(t *testing.T) {
	t.Parallel()
	b, _ := Check(Limit{Cap: 10, Committed: 8, Estimate: 4})
	if b.Remaining != 2 || b.Ratio != 1.2 {
		t.Fatalf("breach = %+v, want remaining 2, ratio 1.2", b)
	}
	b, _ = Check(Limit{Cap: 0, Estimate: 1})
	if !math.IsInf(b.Ratio, 1) {
		t.Fatalf("zero-cap ratio = %v, want +Inf", b.Ratio)
	}
	b, _ = Check(Limit{Cap: math.NaN()})
	if !math.IsInf(b.Ratio, 1) {
		t.Fatalf("invalid ratio = %v, want +Inf so it leads its group", b.Ratio)
	}
}

func usd(group string, c, committed, est float64, soft bool) Limit {
	return Limit{Group: group, Name: group + "/usd", Unit: UnitUSD, Cap: c, Committed: committed, Estimate: est, Soft: soft}
}

func tok(group string, c, committed, est float64, soft bool) Limit {
	return Limit{Group: group, Name: group + "/tokens", Unit: UnitTokens, Cap: c, Committed: committed, Estimate: est, Soft: soft}
}

// TestAdmitRules is one row per requestRules row and per group outcome.
func TestAdmitRules(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		r           Request
		admitted    bool
		rule        string
		refusedName string
		unknown     Unit
		warnings    int
	}{
		{
			name:     "no caps admits",
			r:        Request{},
			admitted: true, rule: RuleWithinCaps,
		},
		{
			name:    "unknown USD estimate under a USD cap refuses",
			r:       Request{Limits: []Limit{tok("org", 100, 0, 1, false), usd("org", 10, 0, 0, false)}, Unknown: []Unit{UnitUSD}},
			rule:    RuleUnknownCapped,
			unknown: UnitUSD,
		},
		{
			name:     "unknown USD estimate under token caps only admits",
			r:        Request{Limits: []Limit{tok("org", 100, 0, 1, false)}, Unknown: []Unit{UnitUSD}, RefuseUnknownUncapped: true},
			admitted: true, rule: RuleWithinCaps,
		},
		{
			name:    "unknown estimate with no cap at all refuses when asked",
			r:       Request{Unknown: []Unit{UnitUSD}, RefuseUnknownUncapped: true},
			rule:    RuleUnknownUncapped,
			unknown: UnitUSD,
		},
		{
			name:     "unknown estimate with no cap at all admits when not asked",
			r:        Request{Unknown: []Unit{UnitUSD}},
			admitted: true, rule: RuleWithinCaps,
		},
		{
			name: "first hard group in order is the one named",
			r: Request{Limits: []Limit{
				usd("member", 1, 1, 0.5, false),
				usd("org", 1, 1, 0.5, false),
			}},
			rule: RuleHardBreach, refusedName: "member/usd",
		},
		{
			name: "soft group warns and the walk goes on to a hard refusal",
			r: Request{Limits: []Limit{
				usd("team", 1, 1, 0.5, true),
				usd("org", 1, 1, 0.5, false),
			}},
			rule: RuleHardBreach, refusedName: "org/usd", warnings: 1,
		},
		{
			name:     "soft breach only admits with a warning",
			r:        Request{Limits: []Limit{usd("team", 1, 1, 0.5, true), usd("org", 10, 1, 0.5, false)}},
			admitted: true, rule: RuleSoftBreachWarned, warnings: 1,
		},
		{
			name: "own-group limits are decided one by one in order",
			r: Request{Limits: []Limit{
				{Name: "daily", Unit: UnitCount, Cap: 100, Committed: 10, Estimate: 1},
				{Name: "monthly", Unit: UnitCount, Cap: 3000, Committed: 3000, Estimate: 1},
				{Name: "concurrency", Unit: UnitCount, Cap: 2, Committed: 2, Estimate: 1},
			}},
			rule: RuleHardBreach, refusedName: "monthly",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			d := Admit(c.r)
			if d.Admitted != c.admitted || d.Rule != c.rule || d.UnknownUnit != c.unknown || len(d.Warnings) != c.warnings {
				t.Fatalf("Admit = %+v, want admitted=%v rule=%q unknown=%q warnings=%d", d, c.admitted, c.rule, c.unknown, c.warnings)
			}
			got := ""
			if d.Refused != nil {
				got = d.Refused.Name
			}
			if got != c.refusedName {
				t.Fatalf("refused = %q, want %q", got, c.refusedName)
			}
		})
	}
}

// TestLeadingUnit pins the gateway's first-unit-exhausted-wins rule (plan
// R2d): within one cap row, the unit reported is the one with the largest
// ratio; an unbreached unit never leads.
func TestLeadingUnit(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		g    []Limit
		unit Unit
		pct  float64
	}{
		{name: "tokens exhaust first", g: []Limit{usd("m", 10, 9, 2, false), tok("m", 1000, 900, 300, false)}, unit: UnitTokens, pct: 1.2},
		{name: "usd exhausts first", g: []Limit{usd("m", 10, 9, 6, false), tok("m", 1000, 900, 300, false)}, unit: UnitUSD, pct: 1.5},
		{name: "only usd breached", g: []Limit{usd("m", 10, 9, 2, false), tok("m", 1000, 0, 10, false)}, unit: UnitUSD, pct: 1.1},
		{name: "equal ratios: the earlier limit leads", g: []Limit{usd("m", 10, 10, 2, false), tok("m", 100, 100, 20, false)}, unit: UnitUSD, pct: 1.2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			d := Admit(Request{Limits: c.g})
			if d.Refused == nil || d.Refused.Unit != c.unit || math.Abs(d.Refused.Ratio-c.pct) > 1e-9 {
				t.Fatalf("Admit = %+v, want refused unit %q at %v", d, c.unit, c.pct)
			}
		})
	}
}

// TestOverSaleNeverExceedsTheCap drives many holders through a ledger that
// serializes like the callers' row locks do and proves the core never sells
// past the cap: exactly cap holds are admitted, the rest refused.
func TestOverSaleNeverExceedsTheCap(t *testing.T) {
	t.Parallel()
	const capUnits, holders = 5, 64
	var (
		mu       sync.Mutex
		used     float64
		admitted int
		wg       sync.WaitGroup
	)
	for i := 0; i < holders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mu.Lock() // the caller's FOR UPDATE row lock
			defer mu.Unlock()
			d := Admit(Request{Limits: []Limit{{Name: "daily", Unit: UnitCount, Cap: capUnits, Committed: used, Estimate: 1}}})
			if d.Admitted {
				used++
				admitted++
			}
		}()
	}
	wg.Wait()
	if admitted != capUnits || used != capUnits {
		t.Fatalf("admitted %d (used %v), want exactly %d", admitted, used, capUnits)
	}
}

// TestSettleRules is one row per settleRules row.
func TestSettleRules(t *testing.T) {
	t.Parallel()
	open := Hold{State: HoldOpen, Estimate: 10}
	cases := []struct {
		name string
		h    Hold
		c    Close
		want Settlement
	}{
		{name: "already final settle is a no-op", h: Hold{State: HoldFinal, Estimate: 10}, c: Close{Outcome: OutcomeSettle, Actual: 3}, want: Settlement{Noop: true, Rule: RuleAlreadyFinal}},
		{name: "already final release is a no-op", h: Hold{State: HoldFinal, Estimate: 10}, c: Close{Outcome: OutcomeRelease}, want: Settlement{Noop: true, Rule: RuleAlreadyFinal}},
		{name: "settle with a NaN actual keeps the worst case", h: open, c: Close{Outcome: OutcomeSettle, Actual: math.NaN()}, want: Settlement{Booked: 10, FreesSlot: true, Rule: RuleUnknownActual}},
		{name: "settle with a negative actual keeps the worst case", h: open, c: Close{Outcome: OutcomeSettle, Actual: -1}, want: Settlement{Booked: 10, FreesSlot: true, Rule: RuleUnknownActual}},
		{name: "settle above the estimate books the overrun", h: open, c: Close{Outcome: OutcomeSettle, Actual: 12}, want: Settlement{Booked: 12, Overrun: 2, FreesSlot: true, Rule: RuleSettleOverrun}},
		{name: "settle below the estimate refunds the rest", h: open, c: Close{Outcome: OutcomeSettle, Actual: 4}, want: Settlement{Booked: 4, Refund: 6, FreesSlot: true, Rule: RuleSettleWithin}},
		{name: "settle at the estimate consumes it all", h: open, c: Close{Outcome: OutcomeSettle, Actual: 10}, want: Settlement{Booked: 10, FreesSlot: true, Rule: RuleSettleWithin}},
		{name: "release refunds the whole hold", h: open, c: Close{Outcome: OutcomeRelease}, want: Settlement{Refund: 10, FreesSlot: true, Rule: RuleReleaseRefunds}},
		{name: "expire refunds the whole hold", h: open, c: Close{Outcome: OutcomeExpire, Actual: 99}, want: Settlement{Refund: 10, FreesSlot: true, Rule: RuleReleaseRefunds}},
		{name: "reconcile books the estimate", h: open, c: Close{Outcome: OutcomeReconcile, Actual: 1}, want: Settlement{Booked: 10, FreesSlot: true, Rule: RuleReconcileHolds}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := Settle(c.h, c.c)
			if err != nil || got != c.want {
				t.Fatalf("Settle = (%+v, %v), want %+v", got, err, c.want)
			}
		})
	}
}

// TestSettleIdempotentByKey models one hold under one key closed twice: the
// second close (a retried stream end, a racing sweep) books nothing.
func TestSettleIdempotentByKey(t *testing.T) {
	t.Parallel()
	for _, o := range []Outcome{OutcomeSettle, OutcomeRelease, OutcomeExpire, OutcomeReconcile} {
		t.Run(string(o), func(t *testing.T) {
			t.Parallel()
			ledger := map[string]Hold{"req-1": {State: HoldOpen, Estimate: 1}}
			booked, refunded := 0.0, 0.0
			for i := 0; i < 2; i++ {
				s, err := Settle(ledger["req-1"], Close{Outcome: o, Actual: 1})
				if err != nil {
					t.Fatal(err)
				}
				if !s.Noop {
					ledger["req-1"] = Hold{State: HoldFinal, Estimate: 1}
				}
				booked += s.Booked
				refunded += s.Refund
			}
			if booked+refunded != 1 {
				t.Fatalf("two closes moved %v booked + %v refunded, want one close of 1", booked, refunded)
			}
		})
	}
}

// TestSettleUnknownOutcome refuses a vocabulary miss before reading the
// hold, so it is never mistaken for an idempotent no-op.
func TestSettleUnknownOutcome(t *testing.T) {
	t.Parallel()
	for _, h := range []Hold{{State: HoldOpen}, {State: HoldFinal}} {
		if _, err := Settle(h, Close{Outcome: "refund"}); !errors.Is(err, ErrUnknownOutcome) {
			t.Fatalf("Settle(%+v) err = %v, want ErrUnknownOutcome", h, err)
		}
	}
}

// TestReplayRules is one row per replayRules row.
func TestReplayRules(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		p    Prior
		want Replay
	}{
		{name: "never seen", p: Prior{}, want: ReplayFresh},
		{name: "settled is a replay even if forwarded", p: Prior{Exists: true, Final: true, Forwarded: true}, want: ReplayRefuseFinal},
		{name: "settled is a replay", p: Prior{Exists: true, Final: true}, want: ReplayRefuseFinal},
		{name: "open and forwarded is in flight", p: Prior{Exists: true, Forwarded: true}, want: ReplayRefuseInFlight},
		{name: "open and not forwarded rejoins", p: Prior{Exists: true}, want: ReplayRejoin},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := ReplayFor(c.p); got != c.want {
				t.Fatalf("ReplayFor(%+v) = %q, want %q", c.p, got, c.want)
			}
		})
	}
}

// TestWindowKey is one row per windowRules row, plus the location rows.
func TestWindowKey(t *testing.T) {
	t.Parallel()
	// 2026-11-01 03:30 UTC is still 2026-10-31 in UTC-8.
	at := time.Date(2026, 11, 1, 3, 30, 0, 0, time.UTC)
	west := time.FixedZone("UTC-8", -8*3600)
	cases := []struct {
		name string
		w    Window
		loc  *time.Location
		want string
		ok   bool
	}{
		{name: "daily UTC", w: WindowDaily, loc: time.UTC, want: "2026-11-01", ok: true},
		{name: "daily nil is UTC", w: WindowDaily, want: "2026-11-01", ok: true},
		{name: "daily in the cap's zone", w: WindowDaily, loc: west, want: "2026-10-31", ok: true},
		{name: "monthly UTC", w: WindowMonthly, want: "2026-11", ok: true},
		{name: "monthly in the cap's zone", w: WindowMonthly, loc: west, want: "2026-10", ok: true},
		{name: "live has one bucket", w: WindowLive, loc: west, want: LiveKey, ok: true},
		{name: "unknown window", w: "weekly", want: "", ok: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, ok := WindowKey(at, c.w, c.loc)
			if got != c.want || ok != c.ok {
				t.Fatalf("WindowKey = (%q, %v), want (%q, %v)", got, ok, c.want, c.ok)
			}
		})
	}
}
