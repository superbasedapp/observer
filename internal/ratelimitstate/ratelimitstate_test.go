package ratelimitstate

import (
	"testing"
	"time"
)

const codexBase = `{"limit_id":"codex","limit_name":null,"primary":{"used_percent":9,"window_minutes":10080,"resets_at":1791047433},"secondary":null,"credits":{"has_credits":false},"plan_type":"prolite","rate_limit_reached_type":null}`

func mustParse(t *testing.T, raw string) Snapshot {
	t.Helper()
	s, ok := Parse(raw)
	if !ok {
		t.Fatalf("Parse(%s) ok=false", raw)
	}
	return s
}

func TestParseShapes(t *testing.T) {
	cases := []struct {
		name        string
		raw         string
		ok          bool
		limit, plan string
		status      string
		windows     int
		summary     string
	}{
		{"codex one window, null plan status", codexBase, true, "codex", "prolite", "", 1, "7d 9% · plan prolite"},
		{"codex two windows", `{"limit_id":"codex","primary":{"used_percent":12,"window_minutes":300,"resets_at":1},"secondary":{"used_percent":40,"window_minutes":10080,"resets_at":2},"plan_type":"pro","rate_limit_reached_type":null}`, true, "codex", "pro", "", 2, "5h 12% · 7d 40% · plan pro"},
		{"codex reached", `{"limit_id":"codex","primary":{"used_percent":100,"window_minutes":300,"resets_at":1},"secondary":null,"plan_type":null,"rate_limit_reached_type":"primary"}`, true, "codex", "", "primary", 1, "5h 100% · status primary"},
		{"cowork", `{"status":"allowed","resetsAt":1780579800,"rateLimitType":"five_hour","overageStatus":"allowed","overageResetsAt":1780574400,"isUsingOverage":false}`, true, "five_hour", "", "allowed", 1, "five_hour allowed · overage allowed"},
		{"not json", `codex`, false, "", "", "", 0, ""},
		{"unrelated json", `{"foo":1}`, false, "", "", "", 0, ""},
		{"empty", ``, false, "", "", "", 0, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, ok := Parse(c.raw)
			if ok != c.ok {
				t.Fatalf("ok=%v want %v", ok, c.ok)
			}
			if !ok {
				return
			}
			if s.LimitID != c.limit || s.Plan != c.plan || s.Status != c.status || len(s.Windows) != c.windows {
				t.Errorf("got %+v", s)
			}
			if got := Summary(s); got != c.summary {
				t.Errorf("Summary=%q want %q", got, c.summary)
			}
		})
	}
}

// TestChangeRules has one case per changeRules row plus the no-change
// jitter cases the live corpus is full of.
func TestChangeRules(t *testing.T) {
	base := mustParse(t, codexBase)
	mod := func(f func(*Snapshot)) Snapshot {
		s := base
		s.Windows = append([]Window(nil), base.Windows...)
		f(&s)
		return s
	}
	cases := []struct {
		name string
		cur  Snapshot
		want string
	}{
		{"identical", base, ""},
		{"null status vs ok is not a change", mod(func(s *Snapshot) { s.Status = "ok" }), ""},
		{"reset jitter 1s", mod(func(s *Snapshot) { s.Windows[0].ResetsAt++ }), ""},
		{"reset jitter 4m", mod(func(s *Snapshot) { s.Windows[0].ResetsAt += 240 }), ""},
		{"reset jitter exactly tolerance", mod(func(s *Snapshot) { s.Windows[0].ResetsAt += int64(ResetTolerance / time.Second) }), ""},
		{"status", mod(func(s *Snapshot) { s.Status = "primary" }), ReasonStatus},
		{"limit", mod(func(s *Snapshot) { s.LimitID = "premium" }), ReasonLimit},
		{"plan", mod(func(s *Snapshot) { s.Plan = "pro" }), ReasonPlan},
		{"overage", mod(func(s *Snapshot) { s.Overage = true }), ReasonOverage},
		{"overage status", mod(func(s *Snapshot) { s.OverageStatus = "rejected" }), ReasonOverage},
		{"window added", mod(func(s *Snapshot) {
			s.Windows = append(s.Windows, Window{Name: "secondary", HasUsed: true, WindowMinutes: 300})
		}), ReasonWindows},
		{"window length changed", mod(func(s *Snapshot) { s.Windows[0].WindowMinutes = 300 }), ReasonWindows},
		{"used percent tick", mod(func(s *Snapshot) { s.Windows[0].UsedPercent = 10 }), ReasonUsedPercent},
		{"used percent float noise", mod(func(s *Snapshot) { s.Windows[0].UsedPercent = 9.2 }), ""},
		{"window rolled", mod(func(s *Snapshot) { s.Windows[0].ResetsAt += 7 * 24 * 3600 }), ReasonReset},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Change(base, c.cur); got != c.want {
				t.Errorf("Change=%q want %q", got, c.want)
			}
		})
	}
}

// TestTrackerEmitRules has one case per emitRules row.
func TestTrackerEmitRules(t *testing.T) {
	base := mustParse(t, codexBase)
	tick := base
	tick.Windows = []Window{base.Windows[0]}
	tick.Windows[0].UsedPercent = 10
	spark := tick
	spark.LimitID = "codex_bengalfox"
	t0 := time.Date(2026, 9, 28, 13, 0, 0, 0, time.UTC)

	var tr Tracker
	steps := []struct {
		name   string
		key    string
		snap   Snapshot
		at     time.Time
		emit   bool
		reason string
	}{
		{"first per key", "s1", base, t0, true, ReasonFirst},
		{"unchanged inside heartbeat", "s1", base, t0.Add(time.Minute), false, ""},
		{"unchanged again", "s1", base, t0.Add(14 * time.Minute), false, ""},
		{"heartbeat", "s1", base, t0.Add(15 * time.Minute), true, ReasonHeartbeat},
		{"change", "s1", tick, t0.Add(16 * time.Minute), true, ReasonUsedPercent},
		{"unchanged after change", "s1", tick, t0.Add(17 * time.Minute), false, ""},
		{"other key is its own first", "s2", tick, t0.Add(17 * time.Minute), true, ReasonFirst},
		{"other limit family is its own stream", "s1", spark, t0.Add(18 * time.Minute), true, ReasonFirst},
		{"back to the first family: unchanged, no alternation noise", "s1", tick, t0.Add(19 * time.Minute), false, ""},
		{"spark repeat unchanged", "s1", spark, t0.Add(20 * time.Minute), false, ""},
		{"zero time never heartbeats", "s1", tick, time.Time{}, false, ""},
	}
	for _, s := range steps {
		emit, reason := tr.Observe(s.key, s.snap, s.at)
		if emit != s.emit || reason != s.reason {
			t.Errorf("%s: Observe=(%v,%q) want (%v,%q)", s.name, emit, reason, s.emit, s.reason)
		}
	}
}
