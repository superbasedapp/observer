package main

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/budgetwarnfile"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgbudget"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestBudgetWarnServiceWarnsOnSubjectCaps (Sol A5-04, D-016): per-tool and
// per-model caps are enforced by the guard, so the developer must be warned at
// the org's 75 / 90 / 100 rungs on them too, each cap on its own ladder, read
// through the guard's accounting (ByTool / ByModel) plus the subject baseline,
// in the composed calendars. An unavailable subject read keeps the last
// evaluation (the A5-07 rule).
func TestBudgetWarnServiceWarnsOnSubjectCaps(t *testing.T) {
	db := filepath.Join(t.TempDir(), "observer.db")
	var mu sync.Mutex
	available := true
	toolUSD, modelTokens := 7.0, int64(700)
	var gotCal guard.BudgetCalendars
	subjectSpend := func(cal guard.BudgetCalendars) (guard.BudgetSnapshot, bool) {
		mu.Lock()
		defer mu.Unlock()
		gotCal = cal
		return guard.BudgetSnapshot{
			ByTool:  map[string]policy.BudgetWindowAmounts{"claude-code": {DailyUSD: toolUSD}, "codex": {DailyUSD: 99}},
			ByModel: map[string]policy.BudgetWindowAmounts{"gpt-5": {MonthlyTokens: modelTokens}},
		}, available
	}
	type notice struct{ title, body string }
	var notices []notice
	svc := newBudgetWarnService(db, func() (guard.BudgetWindowSpend, bool) {
		return guard.BudgetWindowSpend{DailyUSD: 1}, true
	}, func(title, body string) { notices = append(notices, notice{title, body}) }, nil)
	svc.SetSubjectSpend(subjectSpend)
	// An enforcing managed machine holding enforce.budget: the hard tool cap
	// really blocks here, so the 100% sentence may say so.
	svc.SetMachine(func() budgetMachine { return budgetMachine{GuardMode: "enforce", OrgAuthoritative: true} })
	now := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return now }
	ladder := []float64{0.75, 0.9, 1}
	svc.SetComposition([]orgbudget.Origin{{
		Window: "daily", Unit: "usd", Cap: 100, Scope: "member:m1", Period: "calendar_day",
		Timezone: "UTC", Enforcement: "soft", Thresholds: ladder,
	}}, []orgbudget.SubjectCap{
		{
			Kind: orgcontract.BudgetSubjectTool, ID: "claude-code", Window: "daily", CapUSD: 10, BaselineUSD: 0.5,
			ScopeUSD: "member:m1", Enforcement: "hard", Thresholds: ladder, Timezone: "UTC",
		},
		{
			Kind: orgcontract.BudgetSubjectModel, ID: "gpt-5", Window: "monthly", CapTokens: 1000,
			ScopeTokens: "org", Enforcement: "soft", Thresholds: ladder, Timezone: "UTC",
		},
	}, guard.BudgetCalendars{DailyTimezone: "Asia/Kolkata"})

	step := func(tool float64, model int64) []notice {
		mu.Lock()
		toolUSD, modelTokens = tool, model
		mu.Unlock()
		before := len(notices)
		now = now.Add(time.Minute)
		svc.evaluate()
		return notices[before:]
	}
	expect := func(got []notice, want ...string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("notices = %+v, want %d", got, len(want))
		}
		for i, w := range want {
			if !strings.Contains(got[i].body, w) {
				t.Errorf("notice %d body = %q, want it to mention %q", i, got[i].body, w)
			}
		}
	}

	// 7.0 local + 0.5 baseline = 75% of the $10 tool cap exactly; the model is
	// at 70% and the whole caller at 1%: one notice, the tool's.
	first := step(7.0, 700)
	expect(first, "budget for tool claude-code")
	if gotCal.DailyTimezone != "Asia/Kolkata" || gotCal.MonthlyTimezone != "UTC" {
		t.Errorf("subject read calendars = %+v, want the composed engine's", gotCal)
	}
	if !strings.Contains(first[0].title, "75% reached") {
		t.Errorf("title = %q", first[0].title)
	}
	// The model reaches 75% (tokens); the tool holds: only the model speaks.
	expect(step(7.0, 750), "budget for model gpt-5")
	// The tool reaches 90%, then exactly 100% (9.5 + 0.5 baseline).
	expect(step(8.5, 750), "tool claude-code")
	expect(step(9.5, 750), "Further proxied requests, and the next prompt or tool call in tools with a pre-send hook, are blocked")
	// Nothing new: no rung is announced twice.
	expect(step(9.5, 760))

	file, err := budgetwarnfile.Read(budgetwarnfile.StatusPath(db))
	if err != nil || file == nil {
		t.Fatalf("status file: %v", err)
	}
	subjects := map[string]bool{}
	for _, a := range file.Active {
		subjects[a.Subject] = true
	}
	if !subjects["tool:claude-code"] || !subjects["model:gpt-5"] {
		t.Errorf("status file Active = %+v, want both subject warnings", file.Active)
	}

	// An unavailable subject read keeps the file and the dedup state.
	mu.Lock()
	available = false
	mu.Unlock()
	now = now.Add(time.Minute)
	svc.evaluate()
	file2, err := budgetwarnfile.Read(budgetwarnfile.StatusPath(db))
	if err != nil || file2 == nil || len(file2.Active) != len(file.Active) {
		t.Fatalf("after an unavailable subject read the file = %+v err=%v", file2, err)
	}
	mu.Lock()
	available = true
	mu.Unlock()
	expect(step(9.5, 760))
}

// TestBudgetWarnServiceSaysWhatThisMachineDoes pins the 2026-11-18 production
// finding (docs/audits/budget-enforcement-honesty-2026-11-18.md): a $0.01
// hard org cap on a machine whose guard was in OBSERVE mode rendered "(you,
// blocking) ... are blocked" while nothing was blocked. The sentence, the
// file's Blocked bit and the statusline must follow what this machine does:
// one row per machine shape.
func TestBudgetWarnServiceSaysWhatThisMachineDoes(t *testing.T) {
	cases := []struct {
		name        string
		machine     *budgetMachine // nil = no resolver installed
		spend       guard.BudgetWindowSpend
		wantLabel   string
		wantTail    string
		wantBlocked bool
		wantEffect  string
		wantStatus  string
	}{
		{
			name:      "observe mode (the incident)",
			machine:   &budgetMachine{GuardMode: "observe", OrgAuthoritative: true},
			spend:     guard.BudgetWindowSpend{MonthlyUSD: 0.42, LocalMonthlyUSD: 0.42},
			wantLabel: "(you, warning only on this machine)", wantTail: "This machine is in observe mode, so requests are not blocked.",
			wantEffect: "warn_observe", wantStatus: "budget 4200% of $0.01/mo (not blocked)",
		},
		{
			name:      "guard off",
			machine:   &budgetMachine{GuardMode: "off"},
			spend:     guard.BudgetWindowSpend{MonthlyUSD: 0.42, LocalMonthlyUSD: 0.42},
			wantLabel: "(you, warning only on this machine)", wantTail: "The guard is off on this machine, so requests are not blocked.",
			wantEffect: "warn_guard_off", wantStatus: "budget 4200% of $0.01/mo (not blocked)",
		},
		{
			name:      "no machine resolver: nothing here can block",
			spend:     guard.BudgetWindowSpend{MonthlyUSD: 0.42, LocalMonthlyUSD: 0.42},
			wantLabel: "(you, warning only on this machine)", wantTail: "The guard is off on this machine, so requests are not blocked.",
			wantEffect: "warn_guard_off", wantStatus: "budget 4200% of $0.01/mo (not blocked)",
		},
		{
			name:      "enforce, org cap authoritative",
			machine:   &budgetMachine{GuardMode: "enforce", OrgAuthoritative: true},
			spend:     guard.BudgetWindowSpend{MonthlyUSD: 0.42, LocalMonthlyUSD: 0.42},
			wantLabel: "(you, blocking)", wantTail: "in tools with a pre-send hook, are blocked until the period resets",
			wantBlocked: true, wantEffect: "blocks", wantStatus: "budget 4200% of $0.01/mo (blocked)",
		},
		{
			name:      "enforce, org cap lowering only: proxy only",
			machine:   &budgetMachine{GuardMode: "enforce"},
			spend:     guard.BudgetWindowSpend{MonthlyUSD: 0.42, LocalMonthlyUSD: 0.42},
			wantLabel: "(you, blocking)", wantTail: "Tools that do not go through the proxy are not blocked.",
			wantBlocked: true, wantEffect: "blocks_proxied", wantStatus: "budget 4200% of $0.01/mo (blocked)",
		},
		{
			name:      "enforce, over only with a flag-only baseline",
			machine:   &budgetMachine{GuardMode: "enforce", OrgAuthoritative: true},
			spend:     guard.BudgetWindowSpend{MonthlyUSD: 0.02, LocalMonthlyUSD: 0.005, BaselineFlagOnly: true},
			wantLabel: "(you, blocking)", wantTail: "spend from your other machines only warns.",
			wantEffect: "blocks", wantStatus: "budget 200% of $0.01/mo (not blocked)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := filepath.Join(t.TempDir(), "observer.db")
			svc := newBudgetWarnService(db, func() (guard.BudgetWindowSpend, bool) { return tc.spend, true }, nil, nil)
			if tc.machine != nil {
				m := *tc.machine
				svc.SetMachine(func() budgetMachine { return m })
			}
			svc.now = func() time.Time { return time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC) }
			svc.SetComposition([]orgbudget.Origin{{
				Window: "monthly", Unit: "usd", Cap: 0.01, Scope: "member:m1", Period: "calendar_month",
				Timezone: "UTC", Enforcement: "hard",
			}}, nil, guard.BudgetCalendars{})
			svc.evaluate()
			file, err := budgetwarnfile.Read(budgetwarnfile.StatusPath(db))
			if err != nil || file == nil || len(file.Active) != 1 || len(file.Windows) != 1 {
				t.Fatalf("status file = %+v err=%v", file, err)
			}
			n := file.Active[0]
			if !strings.Contains(n.Message, tc.wantLabel) || !strings.Contains(n.Message, tc.wantTail) {
				t.Errorf("message = %q, want %q and %q", n.Message, tc.wantLabel, tc.wantTail)
			}
			if !tc.wantBlocked && strings.Contains(n.Message, "are blocked until") {
				t.Errorf("a machine that cannot block claims blocking: %q", n.Message)
			}
			if n.Blocked != tc.wantBlocked || file.Windows[0].Blocked != tc.wantBlocked {
				t.Errorf("blocked = notice %v / window %v, want %v", n.Blocked, file.Windows[0].Blocked, tc.wantBlocked)
			}
			if n.Effect != tc.wantEffect {
				t.Errorf("effect = %q, want %q", n.Effect, tc.wantEffect)
			}
			if got := budgetStatuslineLabel(budgetwarnfile.StatusPath(db), "usd"); got != tc.wantStatus {
				t.Errorf("statusline = %q, want %q", got, tc.wantStatus)
			}
		})
	}
}

// TestProcessBudgetSubjectSpendReadsTheRegisteredAccounting pins the one
// accounting owner: the warning reader calls exactly the lookup guardwire
// registered, node-wide, with the composed calendars.
func TestProcessBudgetSubjectSpendReadsTheRegisteredAccounting(t *testing.T) {
	db := filepath.Join(t.TempDir(), "observer.db")
	read := processBudgetSubjectSpend(db)
	if _, ok := read(guard.BudgetCalendars{}); ok {
		t.Fatal("no registered accounting must read unavailable, never zero")
	}
	var gotSession string
	var gotCal guard.BudgetCalendars
	registerProcessBudgetAccounting(db, func(sessionID string, a guard.BudgetAccountingContext) (guard.BudgetSnapshot, bool) {
		gotSession, gotCal = sessionID, a.Calendars
		return guard.BudgetSnapshot{ByTool: map[string]policy.BudgetWindowAmounts{"codex": {DailyUSD: 2}}}, true
	})
	t.Cleanup(func() { registerProcessBudgetAccounting(db, nil) })
	snap, ok := read(guard.BudgetCalendars{DailyTimezone: "UTC", MonthlyTimezone: "Europe/Berlin"})
	if !ok || snap.ByTool["codex"].DailyUSD != 2 {
		t.Fatalf("snap = %+v ok=%v", snap, ok)
	}
	if gotSession != "" || gotCal.MonthlyTimezone != "Europe/Berlin" {
		t.Errorf("lookup called with session %q calendars %+v", gotSession, gotCal)
	}
}
