package main

import (
	"context"
	"log/slog"
	"math"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/budgetwarn"
	"github.com/marmutapp/superbased-observer/internal/budgetwarnfile"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guard/notify"
	"github.com/marmutapp/superbased-observer/internal/orgbudget"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// The budget-WARNING boundary (2026-10-02 budget-latency arc, operator
// decisions 2 and 3, orchestrator Q4).
//
// The demo-estate incident: a $0.75/day soft org budget; the developer's spend
// went to 170% and nothing they could see said so. The guard did flag the
// breach, once, at 100%, into guard_events and a desktop notifier on a
// headless VM. This service is the ONE owner of what the developer is told:
//
//   - it walks the org's own signed warn ladder (budgetwarn.Evaluate, e.g.
//     75% / 90% / 100%) for every org-authored window the composition adopted,
//     against the guard's own accounting (guard.BudgetWindowSpendNow - the
//     number enforcement compares, plus the org's cross-machine baseline);
//   - each rung is announced ONCE per budget period, node-wide (the ladder
//     memory is persisted in the status file, so a restart does not
//     re-announce);
//   - it writes ONE file, budget-status.json beside the DB
//     (budgetwarnfile), which every out-of-process surface reads: the prompt
//     hooks (a next-prompt message for hook-capable tools), the statusline,
//     the node dashboard banner/toast (including Terminals);
//   - it answers the node proxy's X-SBO-Budget-Warning response header;
//   - it raises a desktop notification on a new crossing when the node has
//     a desktop (the guard's own duplicate alert for the same flag is
//     suppressed - guard.hasOrgBudgetOrigin).
//
// It never decides anything: a soft cap still admits, a hard cap is still
// the guard's to deny. It only tells.

// budgetWarnMinGap bounds how often an activity burst re-measures spend (the
// accounting lookup is a store query).
const budgetWarnMinGap = 2 * time.Second

// budgetWarnIdleTick re-evaluates with no activity, so a period rollover or a
// baseline change still updates the file.
const budgetWarnIdleTick = 60 * time.Second

type budgetWarnService struct {
	path string
	// fetch is the last organization budget pull (SetFetch), copied into
	// every status file so the local dashboard can show a failing pull.
	fetch  *budgetwarnfile.Fetch
	spend  func() (guard.BudgetWindowSpend, bool)
	notify func(title, body string)
	// display resolves the node's developer cost display ("usd" or
	// "tokens", store.ResolveDeveloperCostDisplay) at each evaluation. Nil
	// means dollars. Set via SetDisplay.
	display func() string
	// subjectSpend reads the per-tool / per-model totals through the guard's
	// own accounting lookup (budgetwarn_subjects.go). Nil = subject caps are
	// not measurable in this process. Set via SetSubjectSpend.
	subjectSpend func(guard.BudgetCalendars) (guard.BudgetSnapshot, bool)
	// machine resolves what THIS node can do about a hard cap (its live
	// guard mode, and whether the org's cap is authoritative here) at each
	// evaluation, so every sentence says what the node will actually do
	// (budget-enforcement honesty, 2026-11-18). Nil = nothing here can block:
	// every hard cap renders warning only. Set via SetMachine.
	machine   func() budgetMachine
	logger    *slog.Logger
	now       func() time.Time
	kick      chan struct{}
	mu        sync.Mutex
	origins   []orgbudget.Origin
	subjects  []orgbudget.SubjectCap
	calendars guard.BudgetCalendars
	state     budgetwarn.State
	snapshot  budgetwarnfile.File
	written   bool
	// admission publishes the managed budget decision the hook path stops on
	// (T-519, budget-admission.json). Nil = nothing is published (no guard
	// in this process). Set via SetAdmission.
	admission        func(now time.Time, subjects []orgbudget.SubjectCap) ([]budgetwarnfile.Stop, bool)
	admissionPath    string
	admissionLast    []budgetwarnfile.Stop
	admissionWritten bool
}

// newBudgetWarnService builds the service over the status file beside dbPath.
// spend is the guard's accounting (nil = no proxy guard in this process: the
// service still writes an honest file with no windows). notify may be nil.
func newBudgetWarnService(dbPath string, spend func() (guard.BudgetWindowSpend, bool), notify func(title, body string), logger *slog.Logger) *budgetWarnService {
	if logger == nil {
		logger = slog.Default()
	}
	s := &budgetWarnService{
		path: budgetwarnfile.StatusPath(dbPath), spend: spend, notify: notify,
		admissionPath: budgetwarnfile.AdmissionPath(dbPath),
		logger:        logger, now: time.Now, kick: make(chan struct{}, 1),
	}
	// Restore the ladder memory so a restart does not re-announce a rung.
	if f, err := budgetwarnfile.Read(s.path); err == nil && f != nil {
		s.state = stateFromFile(f.State)
		s.snapshot = *f
	}
	return s
}

// SetOrigins publishes the org-authored windows the composition adopted. It
// is called on every budget composition (orgBudgetHandle.apply) and triggers
// an evaluation.
func (s *budgetWarnService) SetOrigins(origins []orgbudget.Origin) {
	s.SetComposition(origins, nil, guard.BudgetCalendars{})
}

// SetComposition publishes everything one budget composition adopted that
// carries a warn ladder: the whole-caller windows (origins), the per-tool /
// per-model caps (subjects, Sol A5-04), and the calendars the guard engine
// buckets spend by. One call, so an evaluation never pairs the windows of one
// composition with the subjects of another.
func (s *budgetWarnService) SetComposition(origins []orgbudget.Origin, subjects []orgbudget.SubjectCap, calendars guard.BudgetCalendars) {
	if s == nil {
		return
	}
	calendars = budgetWarnCalendars(calendars.DailyTimezone, calendars.MonthlyTimezone)
	s.mu.Lock()
	changed := !reflect.DeepEqual(s.origins, origins) || !reflect.DeepEqual(s.subjects, subjects) ||
		s.calendars != calendars
	s.origins = append([]orgbudget.Origin(nil), origins...)
	s.subjects = append([]orgbudget.SubjectCap(nil), subjects...)
	s.calendars = calendars
	s.mu.Unlock()
	if changed {
		s.Kick()
	}
}

// budgetAdmissionTick is how often the hook-path admission decision is
// re-taken with no activity. It is much shorter than the warn ladder's idle
// tick because it gates the NEXT prompt of a tool the proxy never sees: a
// minute of lag is a minute of unbudgeted prompts. With no managed hard cap
// composed the decision is a constant (CheckInterventionBudget returns before
// any spend read), so the short tick costs nothing on an ordinary node.
const budgetAdmissionTick = 5 * time.Second

// SetAdmission installs the hook-path admission publisher (T-519). Call before
// Run.
func (s *budgetWarnService) SetAdmission(fn func(now time.Time, subjects []orgbudget.SubjectCap) ([]budgetwarnfile.Stop, bool)) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.admission = fn
	s.mu.Unlock()
}

// publishAdmission takes the managed budget decision and writes
// budget-admission.json when the file on disk does not already say it. An
// unavailable decision keeps the last one: the publisher returns ok=false only
// when it could not ask at all, and a stop must not vanish because one
// evaluation failed. The first pass always writes when a file from an earlier
// daemon exists, so a stale stop cannot outlive the daemon that published it.
//
// The comparison is against the FILE, not the in-memory last decision (D-359,
// review P3-08): a file deleted, truncated or replaced by anything else after
// a publish is re-written on the next tick. A file that carries a stop is
// also re-written every budgetwarnfile.AdmissionRefresh even when the decision
// did not change, because a hook ignores a stop older than
// budgetwarnfile.AdmissionMaxAge (P3-05): a live publisher keeps it fresh.
func (s *budgetWarnService) publishAdmission() {
	s.mu.Lock()
	fn, subjects := s.admission, append([]orgbudget.SubjectCap(nil), s.subjects...)
	written, last := s.admissionWritten, s.admissionLast
	s.mu.Unlock()
	if fn == nil || s.admissionPath == "" {
		return
	}
	now := s.now()
	stops, ok := fn(now, subjects)
	if !ok {
		if !written {
			return
		}
		// Keep the last decision, and keep it fresh on disk.
		stops = last
	}
	if !admissionNeedsWrite(s.admissionPath, stops, now) {
		s.mu.Lock()
		s.admissionWritten, s.admissionLast = true, append([]budgetwarnfile.Stop(nil), stops...)
		s.mu.Unlock()
		return
	}
	if err := budgetwarnfile.WriteAdmission(s.admissionPath, budgetwarnfile.Admission{WrittenAt: now.UTC(), Stops: stops}); err != nil {
		s.logger.Warn("budget admission: could not write the hook admission file", "path", s.admissionPath, "err", err)
		return
	}
	if len(stops) > 0 && !budgetwarnfile.SameStops(last, stops) {
		s.logger.Info("budget admission: hook-capable tools now stop on the managed budget",
			"stops", len(stops), "rule", stops[0].RuleID)
	}
	s.mu.Lock()
	s.admissionWritten, s.admissionLast = true, append([]budgetwarnfile.Stop(nil), stops...)
	s.mu.Unlock()
}

// admissionNeedsWrite reports whether the admission file at path must be
// (re)written to say stops at now. One small read per tick:
//   - missing: write only when there is a stop (a node that never had one
//     gets no file);
//   - unreadable, malformed or a foreign schema: write;
//   - different stops: write;
//   - the same stops, at least one, and the file older than
//     AdmissionRefresh (or otherwise stale): write, to keep it fresh.
func admissionNeedsWrite(path string, stops []budgetwarnfile.Stop, now time.Time) bool {
	prev, err := budgetwarnfile.ReadAdmission(path)
	switch {
	case err != nil:
		return true
	case prev == nil:
		return len(stops) > 0
	case !budgetwarnfile.SameStops(prev.Stops, stops):
		return true
	case len(stops) == 0:
		return false
	default:
		return prev.Stale(now) || now.Sub(prev.WrittenAt) >= budgetwarnfile.AdmissionRefresh
	}
}

// clearBudgetAdmission removes the hook admission file beside dbPath. It is
// called where no publisher will run (an `observer start` with no org budget
// service, `observer unenroll`): a stop with no publisher must not outlive it
// (D-359, review P3-05). A missing file is success.
func clearBudgetAdmission(dbPath string) error {
	path := budgetwarnfile.AdmissionPath(dbPath)
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// SetSubjectSpend installs the per-subject spend reader. Call before Run.
func (s *budgetWarnService) SetSubjectSpend(fn func(guard.BudgetCalendars) (guard.BudgetSnapshot, bool)) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.subjectSpend = fn
	s.mu.Unlock()
}

// budgetMachine is what this node can do about an org cap, resolved live.
type budgetMachine struct {
	// GuardMode is the live guard's mode (off / observe / enforce).
	GuardMode string
	// OrgAuthoritative: a managed node whose grant holds enforce.budget,
	// applying the org's budget ([guard.budget].from_org).
	OrgAuthoritative bool
}

// SetMachine installs the machine resolver. Call before Run.
func (s *budgetWarnService) SetMachine(fn func() budgetMachine) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.machine = fn
	s.mu.Unlock()
}

// machineNow is the current machine facts (a nil resolver can block
// nothing: guard mode off).
func (s *budgetWarnService) machineNow() budgetMachine {
	s.mu.Lock()
	fn := s.machine
	s.mu.Unlock()
	if fn == nil {
		return budgetMachine{GuardMode: "off"}
	}
	return fn()
}

// processBudgetMachine resolves the machine facts from the SHARED per-(process,
// db) guard (lazily, like processGuardBudgetSpend) and the live governance
// grant. No guard is mode off: there is no enforcement point at all.
func processBudgetMachine(dbPath string, fromOrg bool, granted func() bool) func() budgetMachine {
	return func() budgetMachine {
		m := budgetMachine{GuardMode: "off"}
		if g := lookupProcessGuard(dbPath); g != nil {
			m.GuardMode = string(g.Mode())
		}
		m.OrgAuthoritative = fromOrg && granted != nil && granted()
		return m
	}
}

// withMachine stamps the machine facts onto every window: the guard mode and
// the grant are node-wide, the baseline rule is per window (set by its
// builder).
func withMachine(windows []budgetwarn.Window, m budgetMachine) []budgetwarn.Window {
	for i := range windows {
		windows[i].GuardMode = m.GuardMode
		windows[i].OrgAuthoritative = m.OrgAuthoritative
	}
	return windows
}

// SetDisplay installs the developer cost-display resolver every message is
// rendered with (operator ruling 2026-10-02: in token mode a developer sees
// "120% used of the budget", never a dollar figure). Call before Run.
func (s *budgetWarnService) SetDisplay(display func() string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.display = display
	s.mu.Unlock()
}

// displayMode is the current developer cost display (dollars when unset).
func (s *budgetWarnService) displayMode() string {
	s.mu.Lock()
	d := s.display
	s.mu.Unlock()
	if d == nil {
		return budgetwarn.DisplayUSD
	}
	if m := d(); m == budgetwarn.DisplayTokens {
		return m
	}
	return budgetwarn.DisplayUSD
}

// Kick requests an evaluation soon (non-blocking; bursts coalesce).
// budgetFetchFailed is the closed set of pull states that mean the machine
// did not get its organization budget this cycle (the node's own list,
// orgclient budgetpolicy.go). disabled, not_enrolled and no_budget are
// answers, not failures, and ok is the pull working.
var budgetFetchFailed = map[string]bool{
	orgcontract.BudgetFetchUnreachable: true,
	orgcontract.BudgetFetchAuthFailed:  true,
	orgcontract.BudgetFetchChannelOff:  true,
	orgcontract.BudgetFetchUnverified:  true,
}

// SetFetch records this cycle's organization budget pull (budget enforce
// consistency, 2026-11-19) and re-evaluates, so the status file and the
// local dashboard's notice follow it within a cycle. It keeps when the pull
// last worked and when the current run of failures began.
func (s *budgetWarnService) SetFetch(state string, now time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	next := budgetwarnfile.Fetch{State: state}
	if s.fetch != nil {
		next.LastOKAt, next.FailingSince = s.fetch.LastOKAt, s.fetch.FailingSince
	}
	switch {
	case state == orgcontract.BudgetFetchOK:
		next.LastOKAt, next.FailingSince = now.UTC().Truncate(time.Second), time.Time{}
	case budgetFetchFailed[state]:
		if next.FailingSince.IsZero() {
			next.FailingSince = now.UTC().Truncate(time.Second)
		}
	default:
		next.FailingSince = time.Time{}
	}
	changed := s.fetch == nil || *s.fetch != next
	s.fetch = &next
	s.mu.Unlock()
	if changed {
		s.Kick()
	}
}

func (s *budgetWarnService) Kick() {
	if s == nil {
		return
	}
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// Run is the daemon-lifetime loop.
func (s *budgetWarnService) Run(ctx context.Context) {
	if s == nil {
		return
	}
	tick := time.NewTicker(budgetWarnIdleTick)
	defer tick.Stop()
	admit := time.NewTicker(budgetAdmissionTick)
	defer admit.Stop()
	var last time.Time
	s.evaluate()
	for {
		select {
		case <-ctx.Done():
			return
		case <-admit.C:
			s.publishAdmission()
			continue
		case <-tick.C:
		case <-s.kick:
			if wait := budgetWarnMinGap - s.now().Sub(last); wait > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(wait):
				}
			}
		}
		last = s.now()
		s.evaluate()
	}
}

// evaluate measures, walks the ladder, persists, and announces new crossings.
// It also re-takes the hook-path admission decision first, on its own rule
// (publishAdmission), so a warning measurement that is unavailable never holds
// back a stop.
func (s *budgetWarnService) evaluate() {
	s.publishAdmission()
	s.mu.Lock()
	origins := append([]orgbudget.Origin(nil), s.origins...)
	subjects := append([]orgbudget.SubjectCap(nil), s.subjects...)
	calendars, subjectSpend := s.calendars, s.subjectSpend
	prev := s.state
	s.mu.Unlock()

	var windows []budgetwarn.Window
	if len(subjects) > 0 && subjectSpend != nil {
		snap, ok := subjectSpend(calendars)
		if !ok {
			// The same rule as the whole-caller read below (Sol A5-07): an
			// unavailable measurement keeps the last evaluation.
			s.logger.Debug("budget warnings: per-subject spend unavailable; keeping the last evaluation")
			return
		}
		windows = append(windows, budgetWarnSubjectWindows(subjects, snap)...)
	}
	if len(origins) > 0 && s.spend != nil {
		sp, ok := s.spend()
		if !ok {
			// MEASUREMENT UNAVAILABLE is not "no windows" (Sol A5-07, D-016).
			// The guard may be mid-rebuild or its accounting query failed;
			// evaluating an empty window list here would drop every active
			// warning from the status file and forget which rungs were
			// already announced, so the next good read would announce the
			// same rung again. Keep the last state and file untouched; only
			// an authoritative change (origins withdrawn, a period rollover
			// seen on a successful read) may clear them.
			s.logger.Debug("budget warnings: spend unavailable; keeping the last evaluation")
			return
		}
		windows = append(budgetWarnWindows(origins, sp), windows...)
	}
	now := s.now()
	windows = withMachine(windows, s.machineNow())
	st, next := budgetwarn.Evaluate(windows, prev, now)
	// Every developer-facing sentence is rendered in the org's chosen
	// display: the file's Active messages (the prompt-hook notice, `observer
	// guard status`, the dashboard banner) and the desktop notification.
	display := s.displayMode()
	for i := range st.Active {
		st.Active[i].Message = budgetwarn.RenderMessage(st.Active[i], display)
	}
	for i := range st.New {
		st.New[i].Message = budgetwarn.RenderMessage(st.New[i], display)
	}
	s.mu.Lock()
	var fetch *budgetwarnfile.Fetch
	if s.fetch != nil {
		f := *s.fetch
		fetch = &f
	}
	s.mu.Unlock()
	file := budgetwarnfile.File{
		WrittenAt: now.UTC(),
		Display:   display,
		Windows:   fileWindows(st.Windows),
		Active:    fileNotices(st.Active),
		State:     fileState(next),
		Fetch:     fetch,
	}

	s.mu.Lock()
	s.state = next
	unchanged := s.written && sameStatus(s.snapshot, file)
	s.snapshot = file
	s.written = true
	s.mu.Unlock()

	if !unchanged {
		if err := budgetwarnfile.Write(s.path, file); err != nil {
			s.logger.Warn("budget warnings: could not write the status file", "path", s.path, "err", err)
		}
	}
	for _, n := range st.New {
		s.logger.Info("org budget threshold crossed on this node",
			"window", n.Window, "unit", n.Unit, "threshold", n.Threshold, "ratio", round2(n.Ratio),
			"enforcement", n.Enforcement)
		if s.notify != nil {
			s.notify("Observer: org budget "+strconv.Itoa(int(math.Round(n.Threshold*100)))+"% reached", n.Message)
		}
	}
}

// Snapshot returns the last evaluated status (the dashboard reads the file;
// this is for in-process readers such as the proxy header).
func (s *budgetWarnService) Snapshot() budgetwarnfile.File {
	if s == nil {
		return budgetwarnfile.File{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot
}

// HeaderValue renders the X-SBO-Budget-Warning value for a node-proxied
// response: one "<enforcement>/<scope> <pct>%" entry per window at or past a
// warn rung this period, semicolon-separated - the AI gateway's spelling, so a
// client reading the header does not care which chokepoint wrote it. Empty
// when nothing is at a rung.
func (s *budgetWarnService) HeaderValue() string {
	if s == nil {
		return ""
	}
	snap := s.Snapshot()
	var parts []string
	for _, w := range snap.Windows {
		if w.Crossed <= 0 {
			continue
		}
		parts = append(parts, w.Enforcement+"/"+w.Scope+" "+strconv.Itoa(int(math.Round(w.Ratio*100)))+"%")
	}
	return strings.Join(parts, "; ")
}

// processGuardBudgetSpend returns the spend reader over the SHARED
// per-(process, db) guard buildProxy composed - the accounting enforcement
// compares against. Resolved lazily, so a guard built later is still found;
// no guard = no reading (the service then writes an honest empty file).
func processGuardBudgetSpend(dbPath string) func() (guard.BudgetWindowSpend, bool) {
	return func() (guard.BudgetWindowSpend, bool) {
		g := lookupProcessGuard(dbPath)
		if g == nil {
			return guard.BudgetWindowSpend{}, false
		}
		return g.BudgetWindowSpendNow()
	}
}

// budgetWarnDesktopNotifier is the desktop channel when [guard.alerts].desktop
// is on (the notifier itself is a silent no-op on a headless host; the file-
// fed surfaces are what reach a developer there).
func budgetWarnDesktopNotifier(enabled bool) func(title, body string) {
	if !enabled {
		return nil
	}
	return notify.NewDesktop().Notify
}

// budgetWarnWindows joins the adopted org windows with the measured spend.
// When the org's cross-machine baseline may only warn (sp.BaselineFlagOnly),
// a blocking cap is compared by the guard against this machine's own spend
// (policy baselineWithheld), so the window carries that number too.
func budgetWarnWindows(origins []orgbudget.Origin, sp guard.BudgetWindowSpend) []budgetwarn.Window {
	out := make([]budgetwarn.Window, 0, len(origins))
	for _, o := range origins {
		var spent, local float64
		switch o.Window + "|" + o.Unit {
		case "daily|usd":
			spent, local = sp.DailyUSD, sp.LocalDailyUSD
		case "monthly|usd":
			spent, local = sp.MonthlyUSD, sp.LocalMonthlyUSD
		case "daily|tokens":
			spent, local = float64(sp.DailyTokens), float64(sp.LocalDailyTokens)
		case "monthly|tokens":
			spent, local = float64(sp.MonthlyTokens), float64(sp.LocalMonthlyTokens)
		default:
			continue
		}
		out = append(out, budgetwarn.Window{
			Window: o.Window, Unit: o.Unit, Cap: o.Cap, Spent: spent, Scope: o.Scope,
			Enforcement: o.Enforcement, Thresholds: o.Thresholds, Timezone: o.Timezone,
			DeniesOnLocal: sp.BaselineFlagOnly && o.Enforcement == "hard", LocalSpent: local,
		})
	}
	return out
}

func fileWindows(in []budgetwarn.WindowStatus) []budgetwarnfile.Window {
	out := make([]budgetwarnfile.Window, 0, len(in))
	for _, w := range in {
		out = append(out, budgetwarnfile.Window{
			Window: w.Window, Unit: w.Unit, Subject: w.Subject, Period: w.Period, Timezone: w.Timezone, Cap: w.Cap, Spent: round6(w.Spent),
			Ratio: round6(w.Ratio), Scope: w.Scope, Enforcement: w.Enforcement, Level: w.Level, Crossed: w.Crossed,
			Effect: w.Effect, Blocked: w.Blocked, DeniesOnLocal: w.DeniesOnLocal,
		})
	}
	return out
}

func fileNotice(n budgetwarn.Notice) budgetwarnfile.Notice {
	return budgetwarnfile.Notice{
		ID: n.ID, Window: n.Window, Unit: n.Unit, Subject: n.Subject, Period: n.Period, Threshold: n.Threshold,
		Ratio: round6(n.Ratio), Spent: round6(n.Spent), Cap: n.Cap, Scope: n.Scope, Enforcement: n.Enforcement,
		CrossedAt: n.CrossedAt, Level: n.Level, Message: n.Message,
		Effect: n.Effect, Blocked: n.Blocked, DeniesOnLocal: n.DeniesOnLocal,
	}
}

func fileNotices(in []budgetwarn.Notice) []budgetwarnfile.Notice {
	if len(in) == 0 {
		return nil
	}
	out := make([]budgetwarnfile.Notice, 0, len(in))
	for _, n := range in {
		out = append(out, fileNotice(n))
	}
	return out
}

func fileState(st budgetwarn.State) map[string]budgetwarnfile.Notified {
	if len(st.Notified) == 0 {
		return nil
	}
	out := make(map[string]budgetwarnfile.Notified, len(st.Notified))
	for k, v := range st.Notified {
		out[k] = budgetwarnfile.Notified{Threshold: v.Threshold, Notice: fileNotice(v.Notice)}
	}
	return out
}

func stateFromFile(in map[string]budgetwarnfile.Notified) budgetwarn.State {
	if len(in) == 0 {
		return budgetwarn.State{}
	}
	st := budgetwarn.State{Notified: make(map[string]budgetwarn.Notified, len(in))}
	for k, v := range in {
		n := v.Notice
		st.Notified[k] = budgetwarn.Notified{Threshold: v.Threshold, Notice: budgetwarn.Notice{
			ID: n.ID, Window: n.Window, Unit: n.Unit, Subject: n.Subject, Period: n.Period, Threshold: n.Threshold,
			Ratio: n.Ratio, Spent: n.Spent, Cap: n.Cap, Scope: n.Scope, Enforcement: n.Enforcement,
			CrossedAt: n.CrossedAt, Level: n.Level, Message: n.Message,
			Effect: n.Effect, Blocked: n.Blocked, DeniesOnLocal: n.DeniesOnLocal,
		}}
	}
	return st
}

// sameStatus compares two files ignoring WrittenAt, so an idle tick does not
// rewrite the file.
func sameStatus(a, b budgetwarnfile.File) bool {
	a.WrittenAt, b.WrittenAt = time.Time{}, time.Time{}
	return reflect.DeepEqual(a, b)
}

func round6(v float64) float64 { return math.Round(v*1e6) / 1e6 }
func round2(v float64) float64 { return math.Round(v*100) / 100 }
