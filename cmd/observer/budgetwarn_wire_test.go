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
)

// TestBudgetWarnServiceDemoIncident replays the 2026-10-02 demo-estate
// incident through the service: the soft $0.75/day member budget arrives with
// spend already at 96%, the next turn takes it to 168%. The developer must be
// told twice (the 90% rung, then 100%), never again for the same rungs, the
// status file must carry it for the hooks/statusline/dashboard, the proxy
// header must report it, and a restarted service must not re-announce.
func TestBudgetWarnServiceDemoIncident(t *testing.T) {
	db := filepath.Join(t.TempDir(), "observer.db")
	var mu sync.Mutex
	spend := guard.BudgetWindowSpend{DailyUSD: 0.718}
	spendFn := func() (guard.BudgetWindowSpend, bool) {
		mu.Lock()
		defer mu.Unlock()
		return spend, true
	}
	var notices []string
	notify := func(title, body string) { notices = append(notices, title+"|"+body) }
	now := time.Date(2026, 10, 2, 5, 13, 54, 0, time.UTC)

	svc := newBudgetWarnService(db, spendFn, notify, nil)
	svc.now = func() time.Time { return now }
	origins := []orgbudget.Origin{{
		Window: "daily", Unit: "usd", Cap: 0.75, Scope: "member:m1", Period: "calendar_day",
		Timezone: "UTC", Enforcement: "soft", Thresholds: []float64{0.75, 0.9, 1},
	}}
	svc.SetOrigins(origins)
	svc.evaluate()
	if len(notices) != 1 || !strings.Contains(notices[0], "90% reached") || !strings.Contains(notices[0], "Requests are not blocked") {
		t.Fatalf("after budget arrival notices = %q", notices)
	}
	if got := svc.HeaderValue(); got != "soft/member:m1 96%" {
		t.Fatalf("header = %q", got)
	}

	mu.Lock()
	spend.DailyUSD = 1.26
	mu.Unlock()
	now = now.Add(5 * time.Minute)
	svc.evaluate()
	svc.evaluate()
	if len(notices) != 2 || !strings.Contains(notices[1], "100% reached") {
		t.Fatalf("after the expensive turn notices = %q", notices)
	}

	file, err := budgetwarnfile.Read(budgetwarnfile.StatusPath(db))
	if err != nil || file == nil || len(file.Active) != 1 || file.Active[0].Threshold != 1 {
		t.Fatalf("status file = %+v %v", file, err)
	}
	if !strings.Contains(file.Active[0].Message, "168% used") {
		t.Fatalf("active message = %q", file.Active[0].Message)
	}

	// A restart restores the ladder memory: nothing is re-announced.
	restarted := newBudgetWarnService(db, spendFn, notify, nil)
	restarted.now = func() time.Time { return now.Add(time.Minute) }
	restarted.SetOrigins(origins)
	restarted.evaluate()
	if len(notices) != 2 {
		t.Fatalf("restart re-announced: %q", notices)
	}

	// Withdrawn org budget: the file says so (no windows), header empty.
	restarted.SetOrigins(nil)
	restarted.evaluate()
	if restarted.HeaderValue() != "" {
		t.Fatal("no org windows must stamp no header")
	}
	file, _ = budgetwarnfile.Read(budgetwarnfile.StatusPath(db))
	if file == nil || len(file.Windows) != 0 || len(file.Active) != 0 {
		t.Fatalf("withdrawn budget file = %+v", file)
	}
}

func TestBudgetWarnServiceNilSafe(t *testing.T) {
	var s *budgetWarnService
	s.SetOrigins(nil)
	s.Kick()
	if s.HeaderValue() != "" || len(s.Snapshot().Windows) != 0 {
		t.Fatal("nil service must be inert")
	}
}

// TestBudgetWarnServiceTokenDisplay pins the org's developer cost display on
// every sentence the service produces (operator ruling 2026-10-02): in token
// mode the status file's messages (the prompt-hook notice, `observer guard
// status`, the dashboard banner) and the desktop notification say "NN% used of
// the budget", never a dollar figure; the file records the display; a flip
// back to dollars re-renders on the next evaluation.
func TestBudgetWarnServiceTokenDisplay(t *testing.T) {
	db := filepath.Join(t.TempDir(), "observer.db")
	spendFn := func() (guard.BudgetWindowSpend, bool) { return guard.BudgetWindowSpend{DailyUSD: 0.90}, true }
	var notices []string
	svc := newBudgetWarnService(db, spendFn, func(title, body string) { notices = append(notices, body) }, nil)
	svc.now = func() time.Time { return time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC) }
	display := "tokens"
	svc.SetDisplay(func() string { return display })
	svc.SetOrigins([]orgbudget.Origin{{
		Window: "daily", Unit: "usd", Cap: 0.75, Scope: "member:m1", Period: "calendar_day",
		Timezone: "UTC", Enforcement: "soft", Thresholds: []float64{1},
	}})
	svc.evaluate()

	cases := []struct {
		display     string
		wantMessage string
		wantLabel   string
	}{
		{"tokens", "Org daily budget (you, warning only): 120% used of the budget. Requests are not blocked.", "budget 120%"},
		{"usd", "Org daily budget (you, warning only): 120% used - $0.90 of $0.75. Requests are not blocked.", "budget 120% of $0.75/day"},
	}
	for i, c := range cases {
		display = c.display
		svc.evaluate()
		file, err := budgetwarnfile.Read(budgetwarnfile.StatusPath(db))
		if err != nil || file == nil || len(file.Active) != 1 {
			t.Fatalf("%s: status file = %+v %v", c.display, file, err)
		}
		if file.Display != c.display {
			t.Errorf("%s: file display = %q", c.display, file.Display)
		}
		if file.Active[0].Message != c.wantMessage {
			t.Errorf("%s: message = %q\nwant %q", c.display, file.Active[0].Message, c.wantMessage)
		}
		// "" = the statusline falls back to the display the file recorded.
		if got := budgetStatuslineLabel(budgetwarnfile.StatusPath(db), ""); got != c.wantLabel {
			t.Errorf("%s: statusline label = %q, want %q", c.display, got, c.wantLabel)
		}
		if i == 0 && (len(notices) != 1 || strings.Contains(notices[0], "$")) {
			t.Errorf("token-mode desktop notification = %q", notices)
		}
	}
}

// TestBudgetStatuslineLabel pins the statusline segment text in both
// developer cost displays.
func TestBudgetStatuslineLabel(t *testing.T) {
	dir := t.TempDir()
	p := budgetStatusPathInDir(dir)
	if budgetStatuslineLabel(p, "") != "" {
		t.Fatal("no file = no segment")
	}
	cases := []struct {
		w       budgetwarnfile.Window
		display string
		want    string
	}{
		{budgetwarnfile.Window{Window: "daily", Unit: "usd", Cap: 0.75, Ratio: 1.68, Crossed: 1, Enforcement: "soft"}, "usd", "budget 168% of $0.75/day"},
		{budgetwarnfile.Window{Window: "daily", Unit: "usd", Cap: 0.75, Ratio: 1.68, Crossed: 1, Enforcement: "soft"}, "tokens", "budget 168%"},
		{budgetwarnfile.Window{Window: "monthly", Unit: "tokens", Cap: 1e6, Ratio: 0.96, Crossed: 0.9, Enforcement: "soft"}, "usd", "budget 96% of 1,000,000 tokens/mo"},
		{budgetwarnfile.Window{Window: "monthly", Unit: "tokens", Cap: 1e6, Ratio: 0.96, Crossed: 0.9, Enforcement: "soft"}, "tokens", "budget 96% of 1,000,000 tokens/mo"},
		{budgetwarnfile.Window{Window: "daily", Unit: "usd", Cap: 5, Ratio: 1.1, Crossed: 1, Enforcement: "hard", Effect: "blocks", Blocked: true}, "usd", "budget 110% of $5.00/day (blocked)"},
		{budgetwarnfile.Window{Window: "daily", Unit: "usd", Cap: 5, Ratio: 1.1, Crossed: 1, Enforcement: "hard", Effect: "blocks", Blocked: true}, "tokens", "budget 110% (blocked)"},
		// A hard cap this machine does not block (observe mode) never reads
		// "(blocked)"; a file from an older daemon (no effect) says neither.
		{budgetwarnfile.Window{Window: "daily", Unit: "usd", Cap: 5, Ratio: 1.1, Crossed: 1, Enforcement: "hard", Effect: "warn_observe"}, "usd", "budget 110% of $5.00/day (not blocked)"},
		{budgetwarnfile.Window{Window: "daily", Unit: "usd", Cap: 5, Ratio: 1.1, Crossed: 1, Enforcement: "hard"}, "usd", "budget 110% of $5.00/day"},
		{budgetwarnfile.Window{Window: "daily", Unit: "usd", Cap: 5, Ratio: 0.1, Crossed: 0, Enforcement: "soft"}, "usd", ""},
		{budgetwarnfile.Window{Window: "daily", Unit: "usd", Cap: 5, Ratio: 0.1, Crossed: 0, Enforcement: "soft"}, "tokens", ""},
	}
	for _, c := range cases {
		if err := budgetwarnfile.Write(p, budgetwarnfile.File{Windows: []budgetwarnfile.Window{c.w}}); err != nil {
			t.Fatal(err)
		}
		if got := budgetStatuslineLabel(p, c.display); got != c.want {
			t.Errorf("%s: label = %q, want %q", c.display, got, c.want)
		}
	}
}

// TestBudgetWarnServiceKeepsStateWhenSpendIsUnavailable (Sol A5-07, D-016): a
// transient failure to read spend (the guard mid-rebuild, a failed accounting
// query) must neither remove the active warning from the status file nor
// re-arm the rung, so the next good read does not announce it again.
func TestBudgetWarnServiceKeepsStateWhenSpendIsUnavailable(t *testing.T) {
	db := filepath.Join(t.TempDir(), "observer.db")
	var mu sync.Mutex
	available := true
	spendFn := func() (guard.BudgetWindowSpend, bool) {
		mu.Lock()
		defer mu.Unlock()
		return guard.BudgetWindowSpend{DailyUSD: 0.70}, available
	}
	var notices []string
	svc := newBudgetWarnService(db, spendFn, func(title, body string) { notices = append(notices, title) }, nil)
	now := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return now }
	svc.SetOrigins([]orgbudget.Origin{{
		Window: "daily", Unit: "usd", Cap: 0.75, Scope: "member:m1", Period: "calendar_day",
		Timezone: "UTC", Enforcement: "soft", Thresholds: []float64{0.75, 0.9, 1},
	}})
	svc.evaluate()
	if len(notices) != 1 || !strings.Contains(notices[0], "90% reached") {
		t.Fatalf("first read notices = %q", notices)
	}

	mu.Lock()
	available = false
	mu.Unlock()
	now = now.Add(time.Minute)
	svc.evaluate()
	file, err := budgetwarnfile.Read(budgetwarnfile.StatusPath(db))
	if err != nil || file == nil || len(file.Active) != 1 || file.Active[0].Threshold != 0.9 {
		t.Fatalf("after an unavailable read the status file = %+v err=%v; the 90%% warning must stay", file, err)
	}
	if svc.HeaderValue() == "" {
		t.Error("the proxy header lost the active warning on an unavailable read")
	}

	mu.Lock()
	available = true
	mu.Unlock()
	now = now.Add(time.Minute)
	svc.evaluate()
	if len(notices) != 1 {
		t.Fatalf("the same rung was announced again after a transient failure: %q", notices)
	}
}

// TestBudgetWarnServiceRecordsTheBudgetPull: the status file carries the
// machine's last organization budget pull (budget enforce consistency,
// 2026-11-19), so the local dashboard can say when it fails: when it last
// worked, and when the current run of failures began. An answer that is not
// a failure (disabled, no budget) clears the run; nil is inert.
func TestBudgetWarnServiceRecordsTheBudgetPull(t *testing.T) {
	db := filepath.Join(t.TempDir(), "observer.db")
	svc := newBudgetWarnService(db, nil, nil, nil)
	t0 := time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC)
	read := func() *budgetwarnfile.Fetch {
		t.Helper()
		svc.evaluate()
		f, err := budgetwarnfile.Read(budgetwarnfile.StatusPath(db))
		if err != nil || f == nil {
			t.Fatalf("read status file: %v", err)
		}
		return f.Fetch
	}
	svc.SetFetch("ok", t0)
	if f := read(); f == nil || f.State != "ok" || !f.LastOKAt.Equal(t0) || !f.FailingSince.IsZero() {
		t.Fatalf("after ok: %+v", f)
	}
	svc.SetFetch("unreachable", t0.Add(time.Minute))
	svc.SetFetch("unreachable", t0.Add(3*time.Minute))
	if f := read(); f.State != "unreachable" || !f.LastOKAt.Equal(t0) || !f.FailingSince.Equal(t0.Add(time.Minute)) {
		t.Fatalf("after two failures: %+v", f)
	}
	svc.SetFetch("no_budget", t0.Add(4*time.Minute))
	if f := read(); f.State != "no_budget" || !f.FailingSince.IsZero() {
		t.Fatalf("after an answer: %+v", f)
	}
	var none *budgetWarnService
	none.SetFetch("unreachable", t0)
}
