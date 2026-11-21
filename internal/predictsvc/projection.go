package predictsvc

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/budgetwarnfile"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/planlimits"
	"github.com/marmutapp/superbased-observer/internal/planlimitssvc"
	"github.com/marmutapp/superbased-observer/internal/predict"
	"github.com/marmutapp/superbased-observer/internal/sessiongauge"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Projection is the run-out projection half of the predict response
// (additive: older consumers ignore it). The math is internal/predict's
// ProjectLimit / ProjectBudget; this package only gathers the inputs through
// their owning seams:
//
//   - the limit reading: the newer of the session's limit gauge (the proxy's
//     limit_snapshots or the tool's own transcript, through the same ladder
//     the gauge uses) and the Plans & limits page model (which merges those
//     with the status line and polled sources), read through
//     planlimitssvc.Service.Status, never a second reader of its tables;
//   - the node's own budget: [guard.budget] with the spend the existing
//     guard budget surface measures (GuardBudgetSpend / GuardBudgetTokens);
//   - the org budget: the daemon-owned budget-status.json (budgetwarnfile),
//     the one file every node surface reads its composed org windows from,
//     placed on each cap's own calendar (orgPeriodBounds);
//   - the captured usage: store.LoadUsageRows over the deduplicated
//     api_turns and token_usage rows.
type Projection struct {
	// Limits is the weekly window then the 5-hour window, each present only
	// when some reading exists for it.
	Limits []predict.Projection `json:"limits"`
	// Budgets is every budget in force, tightest first. Empty means no
	// budget is in force (never "under budget").
	Budgets []predict.Projection `json:"budgets"`
	// CountedTools are the tools whose sessions count toward the limit
	// windows (the tools that draw from the same plan).
	CountedTools []string `json:"counted_tools,omitempty"`
}

// Deps is what Build reads besides the session. The dashboard handler and
// `observer predict` both fill it, so the API and the CLI print one
// derivation, never two engines.
type Deps struct {
	// Store is the node database seam (usage rows, guard budget spend).
	Store *store.Store
	// Config is the node's loaded config: its [guard.budget] caps and the DB
	// path budget-status.json sits beside. nil means no budget is read.
	Config *config.Config
	// Plans is the Plans & limits page model; nil skips the card merge.
	Plans PlanStatusReader
	// Now is the clock.
	Now time.Time
}

// PlanStatusReader is the one Plans & limits read the projection makes (a
// database read of the page model, never a poll).
type PlanStatusReader interface {
	Status(ctx context.Context) (planlimitssvc.View, error)
}

// LoadLimitGauge resolves the limit gauge for a session: it loads the two
// observations the shared ladder reads and hands them to sessiongauge.Limit,
// which owns the ladder (audited no-source finding -> proxy window ->
// transcript window -> no_window / needs_proxy).
//
//   - Proxy: the newest proxy-captured snapshot for the session tool's
//     provider, ATTRIBUTED to the tool that observed it (a node-wide
//     per-provider read would leak one tool's subscription gauge, e.g. Claude
//     Code's 5h/weekly, onto every other anthropic-default tool's session).
//   - Transcript: the tool's own transcript-captured rate_limits (codex
//     token_count -> ActionRateLimit rows); st.LatestRateLimitWindows is
//     ok=false for any tool that does not emit those rows.
//
// A load error degrades to "no observation", never an error.
func LoadLimitGauge(ctx context.Context, st *store.Store, tool, sessionID string, now time.Time) sessiongauge.LimitGauge {
	in := sessiongauge.LimitInput{Tool: tool, Now: now}
	if snap, ok, err := st.LatestLimitSnapshotForTool(ctx, sessiongauge.ProviderForTool(tool), tool); err == nil && ok {
		in.Proxy = &sessiongauge.Window{
			ObservedAt:   snap.ObservedAt,
			Window5hUtil: snap.Window5hUtil, Window5hReset: snap.Window5hReset,
			Window7dUtil: snap.Window7dUtil, Window7dReset: snap.Window7dReset,
		}
	}
	if w, found, err := st.LatestRateLimitWindows(ctx, tool, sessionID); err == nil && found {
		in.Transcript = &sessiongauge.Window{
			ObservedAt:   w.ObservedAt,
			Window5hUtil: w.Window5hUtil, Window5hReset: w.Window5hReset,
			Window7dUtil: w.Window7dUtil, Window7dReset: w.Window7dReset,
		}
	}
	return sessiongauge.Limit(in)
}

// usageLoader memoizes LoadUsageRows within one request: several windows
// share a range (a daily dollar and a daily token cap).
type usageLoader struct {
	ctx   context.Context
	st    *store.Store
	cache map[string][]predict.UsageRow
}

func (u *usageLoader) load(tools []string, since, until time.Time) ([]predict.UsageRow, bool) {
	if since.IsZero() || !until.After(since) {
		return nil, true
	}
	key := strings.Join(tools, ",") + "|" + since.UTC().Format(time.RFC3339Nano) + "|" + until.UTC().Format(time.RFC3339Nano)
	if rows, ok := u.cache[key]; ok {
		return rows, true
	}
	rows, err := u.st.LoadUsageRows(u.ctx, tools, since, until)
	if err != nil {
		return nil, false
	}
	u.cache[key] = rows
	return rows, true
}

// Build assembles the run-out projection for one session.
func Build(ctx context.Context, d Deps, tool, sessionID string, gauge sessiongauge.LimitGauge, est predict.EstimateResult) Projection {
	now, st := d.Now, d.Store
	out := Projection{Limits: []predict.Projection{}, Budgets: []predict.Projection{}}
	u := &usageLoader{ctx: ctx, st: st, cache: map[string][]predict.UsageRow{}}
	msg := predict.MessageCostOf(est)

	// An audited no-local-source tool has no limit reading by construction.
	if !gauge.NoSource {
		readings := gaugeReadings(gauge)
		planTools := mergePlanReadings(ctx, d.Plans, tool, readings)
		out.CountedTools = planTools
		if len(out.CountedTools) == 0 {
			out.CountedTools = []string{tool}
		}
		for _, k := range predict.LimitKinds {
			r, ok := readings[k.Key]
			if !ok {
				continue
			}
			in := predict.LimitInput{Now: now, Reading: r, SessionID: sessionID, Message: msg}
			b := predict.LimitBounds(r, now)
			if b.State == predict.StateLive || b.State == predict.StateResetInferred {
				var ok1, ok2, ok3 bool
				in.Window, ok1 = u.load(out.CountedTools, b.Start, now)
				in.Previous, ok2 = u.load(out.CountedTools, b.PrevStart, b.PrevEnd)
				ok3 = true
				if b.SinceReading {
					in.SinceReading, ok3 = u.load(out.CountedTools, r.ObservedAt, now)
				}
				if !ok1 || !ok2 || !ok3 {
					continue
				}
			}
			out.Limits = append(out.Limits, predict.ProjectLimit(in))
		}
	}

	for _, w := range budgetWindows(ctx, d.Config, st, tool, sessionID, now) {
		in := predict.BudgetInput{Now: now, Window: w, SessionID: sessionID, Message: msg}
		b := predict.BudgetBounds(w, now)
		if b.State != predict.StateSession {
			var tools []string
			if strings.HasPrefix(w.Subject, "tool:") {
				tools = []string{strings.TrimPrefix(w.Subject, "tool:")}
			}
			var ok1, ok2 bool
			in.Rows, ok1 = u.load(tools, w.Start, now)
			in.Previous, ok2 = u.load(tools, b.PrevStart, b.PrevEnd)
			if !ok1 || !ok2 {
				continue
			}
		}
		out.Budgets = append(out.Budgets, predict.ProjectBudget(in))
	}
	sort.SliceStable(out.Budgets, func(i, j int) bool {
		return fracOr0(out.Budgets[i].UsedFrac) > fracOr0(out.Budgets[j].UsedFrac)
	})
	return out
}

func fracOr0(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

// gaugeReadings maps the session's limit gauge onto readings.
func gaugeReadings(g sessiongauge.LimitGauge) map[string]predict.LimitReading {
	out := map[string]predict.LimitReading{}
	if !g.Available {
		return out
	}
	var at time.Time
	if g.ObservedAtUnix != nil {
		at = time.Unix(*g.ObservedAtUnix, 0).UTC()
	}
	add := func(key string, util *float64, reset *int64) {
		if util == nil {
			return
		}
		r := predict.LimitReading{Key: key, UsedFrac: util, ObservedAt: at, Source: g.Source}
		if reset != nil && *reset > 0 {
			r.ResetsAt = time.Unix(*reset, 0).UTC()
		}
		out[key] = r
	}
	add("5h", g.Window5hUtil, g.Window5hReset)
	add("weekly", g.Window7dUtil, g.Window7dReset)
	return out
}

// planProvidersFor returns the Plans & limits catalogue rows whose plan the
// tool draws from (ProviderDef.Tools, the catalogue's own capability data)
// and the union of their tools.
func planProvidersFor(tool string) (map[string]bool, []string) {
	provs := map[string]bool{}
	toolSet := map[string]bool{}
	for _, p := range planlimits.Providers {
		for _, t := range p.Tools {
			if t == tool {
				provs[p.ID] = true
				for _, t2 := range p.Tools {
					toolSet[t2] = true
				}
				break
			}
		}
	}
	tools := make([]string, 0, len(toolSet))
	for t := range toolSet {
		tools = append(tools, t)
	}
	sort.Strings(tools)
	return provs, tools
}

// mergePlanReadings replaces a gauge reading with the Plans & limits card's
// when the card's reading of that window is newer, and returns the tools
// that draw from the plan. The card is used only when exactly one card of
// the plan carries a 5-hour or weekly window: with several accounts of one
// plan on this machine, which one this session used is not known here, so
// the session's own gauge stays.
func mergePlanReadings(ctx context.Context, plans PlanStatusReader, tool string, readings map[string]predict.LimitReading) []string {
	provs, tools := planProvidersFor(tool)
	if plans == nil || len(provs) == 0 {
		return tools
	}
	view, err := plans.Status(ctx)
	if err != nil {
		return tools
	}
	var match []planlimits.Card
	for _, c := range view.Cards {
		if !provs[c.Provider] {
			continue
		}
		for _, w := range c.Windows {
			if w.Key == "5h" || w.Key == "weekly" {
				match = append(match, c)
				break
			}
		}
	}
	if len(match) != 1 {
		return tools
	}
	for _, w := range match[0].Windows {
		if w.Key != "5h" && w.Key != "weekly" {
			continue
		}
		frac := w.UsedFrac
		if frac == nil && w.Used != nil && w.Limit != nil && *w.Limit > 0 {
			v := *w.Used / *w.Limit
			frac = &v
		}
		if frac == nil || w.ResetsAt == nil {
			continue
		}
		cur, have := readings[w.Key]
		if have && !w.ObservedAt.After(cur.ObservedAt) {
			continue
		}
		r := predict.LimitReading{Key: w.Key, UsedFrac: frac, ResetsAt: w.ResetsAt.UTC(), ObservedAt: w.ObservedAt.UTC(), Source: "plans:" + w.Source}
		if w.Length != nil {
			r.Length = *w.Length
		}
		readings[w.Key] = r
	}
	return tools
}

// budgetWindows lists every budget in force: the node's own [guard.budget]
// caps (measured as the guard budget surface measures them) and the org
// windows the daemon composed (budget-status.json). A window from a past
// period (the daemon has not re-measured since the period rolled) is left
// out rather than shown with a stale reading.
func budgetWindows(ctx context.Context, conf *config.Config, st *store.Store, tool, sessionID string, now time.Time) []predict.BudgetWindow {
	if conf == nil {
		return nil
	}
	cfg := *conf
	var out []predict.BudgetWindow
	b := cfg.Guard.Budget
	dayStart := now.UTC().Truncate(24 * time.Hour)
	weekStart := now.Add(-7 * 24 * time.Hour)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	enforcement := "soft"
	if b.Hard {
		enforcement = "hard"
	}
	type local struct {
		key     string
		usd     float64
		tokens  int64
		start   time.Time
		reset   time.Time
		rolling bool
	}
	locals := []local{
		{"session", b.SessionUSD, b.SessionTokens, time.Time{}, time.Time{}, false},
		{"daily", b.DailyUSD, b.DailyTokens, dayStart, dayStart.Add(24 * time.Hour), false},
		{"weekly", b.WeeklyUSD, b.WeeklyTokens, weekStart, time.Time{}, true},
		{"monthly", b.MonthlyUSD, b.MonthlyTokens, monthStart, monthStart.AddDate(0, 1, 0), false},
	}
	anyUSD, anyTok := false, false
	for _, l := range locals {
		anyUSD = anyUSD || l.usd > 0
		anyTok = anyTok || l.tokens > 0
	}
	if anyUSD || anyTok {
		spend, serr := st.GuardBudgetSpend(ctx, sessionID, dayStart, weekStart, monthStart)
		tok, terr := st.GuardBudgetTokens(ctx, sessionID, dayStart, weekStart, monthStart)
		spent := map[string]float64{"session": spend.SessionUSD, "daily": spend.DailyUSD, "weekly": spend.WeeklyUSD, "monthly": spend.MonthlyUSD}
		used := map[string]int64{"session": tok.SessionTokens, "daily": tok.DailyTokens, "weekly": tok.WeeklyTokens, "monthly": tok.MonthlyTokens}
		for _, l := range locals {
			w := predict.BudgetWindow{Key: l.key, Origin: "node", Start: l.start, Reset: l.reset, Rolling: l.rolling, Enforcement: enforcement}
			if l.rolling {
				w.Length = 7 * 24 * time.Hour
			}
			if l.usd > 0 && serr == nil {
				uw := w
				uw.Unit, uw.Cap, uw.Spent = "usd", l.usd, spent[l.key]
				out = append(out, uw)
			}
			if l.tokens > 0 && terr == nil {
				tw := w
				tw.Unit, tw.Cap, tw.Spent = "tokens", float64(l.tokens), float64(used[l.key])
				out = append(out, tw)
			}
		}
	}

	file, ferr := budgetwarnfile.Read(budgetwarnfile.StatusPath(cfg.Observer.DBPath))
	if ferr != nil || file == nil {
		return out
	}
	for _, fw := range file.Windows {
		if fw.Cap <= 0 || (fw.Unit != "usd" && fw.Unit != "tokens") {
			continue
		}
		if fw.Subject != "" && fw.Subject != "tool:"+tool {
			continue // a cap on another tool or on a model this view does not split by
		}
		start, reset, assumed, ok := orgPeriodBounds(fw.Window, fw.Period, fw.Timezone, now)
		if !ok {
			continue
		}
		out = append(out, predict.BudgetWindow{
			Key: fw.Window, Origin: "org", Unit: fw.Unit, Cap: fw.Cap, Spent: fw.Spent,
			Start: start, Reset: reset, Scope: fw.Scope, Enforcement: fw.Enforcement, Subject: fw.Subject,
			TimezoneAssumed: assumed, OtherMachines: true,
		})
	}
	return out
}

// orgPeriodBounds turns an org window's period key ("2006-01-02" daily,
// "2006-01" monthly) into a start and reset in the cap's own timezone: the
// zone the daemon named the period in (budget-status.json "timezone", written
// as "UTC" for a UTC cap), bucketed by predict.CalendarBounds, the same
// calendar the AI gateway buckets its ledger on. ok=false for an unknown
// window or a period that is not the current one in that zone.
//
// A file from a daemon that predates the timezone field carries none: the
// period is then read as UTC, give or take the day a timezone can be off
// UTC (orgPeriodBoundsUTC), and assumed reports it, so the projection carries
// its timezone_assumed_utc note. assumed is also true when the named zone
// cannot be loaded here (UTC was used, as the daemon itself did).
func orgPeriodBounds(window, period, tz string, now time.Time) (start, reset time.Time, assumed, ok bool) {
	if tz == "" {
		start, reset, ok = orgPeriodBoundsUTC(window, period, now)
		return start, reset, true, ok
	}
	cp, known := predict.CalendarBounds(window, tz, now)
	if !known || cp.Key != period {
		return start, reset, false, false
	}
	return cp.Start, cp.Reset, !cp.ZoneHonoured, true
}

// orgPeriodBoundsUTC reads a period key with no timezone as UTC (a status
// file from an older daemon). ok=false for an unknown window or a period that
// is not the current one, give or take a day.
func orgPeriodBoundsUTC(window, period string, now time.Time) (start, reset time.Time, ok bool) {
	layouts := map[string]struct {
		layout string
		next   func(time.Time) time.Time
	}{
		"daily":   {"2006-01-02", func(t time.Time) time.Time { return t.AddDate(0, 0, 1) }},
		"monthly": {"2006-01", func(t time.Time) time.Time { return t.AddDate(0, 1, 0) }},
	}
	l, known := layouts[window]
	if !known {
		return start, reset, false
	}
	t, err := time.Parse(l.layout, period)
	if err != nil {
		return start, reset, false
	}
	reset = l.next(t)
	// The cap's timezone may be up to a day off UTC: accept the period
	// while now is within it, give or take that day.
	if now.Before(t.Add(-24*time.Hour)) || !now.Before(reset.Add(24*time.Hour)) {
		return start, reset, false
	}
	return t, reset, true
}
