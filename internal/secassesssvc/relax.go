package secassesssvc

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// relax.go is the orchestration of a run's relaxations in force (plan section
// 13.5): the reconcile pass the daemon-lifetime loop and the runs list call.
// The decision is secassess.RelaxStep, a pure table; this file only gathers
// the inputs from the injected ports, applies the table's action through them
// and records the result on the run. The ports are plain functions over plain
// values: the store-backed ones live in the dashboard package, so this package
// imports neither the store nor the guard.

// Ports are the reconcile pass's injected I/O.
type Ports struct {
	// Now is the clock.
	Now func() time.Time
	// Terminal says whether a run's terminal handle is live and, for a live
	// one, the session it resolved to and the confidence of that link
	// (0 when none). A nil Terminal reads every terminal as gone, the fail
	// closed answer.
	Terminal func(handle string) (live bool, sessionID string, confidence float64)
	// CreateApproval inserts the approval row only when its key is absent
	// (store.CreateApprovalIfAbsent). created is false when the key is taken.
	CreateApproval func(ctx context.Context, rule, scope, sessionID, projectHash, grantedBy string, expires time.Time) (id int64, created bool, err error)
	// RenewApproval and DeleteApproval touch only the row the run created
	// (id, grantor and last-written expiry).
	RenewApproval  func(ctx context.Context, id int64, grantedBy string, was, now time.Time) (bool, error)
	DeleteApproval func(ctx context.Context, id int64, grantedBy string, expires time.Time) (bool, error)
	// Event writes one lifecycle audit row (store.RecordSecAssessEvent).
	Event func(ctx context.Context, phase, projectHash, sessionID, detail string) error
	// Count counts the verdicts the run's relaxations changed.
	Count func(ctx context.Context, grantedBy string, sessions, rules []string, since, until time.Time) (exact, approx int, err error)
	// Close closes a run's terminal (the launch manager's Close). The pass uses
	// it to close a terminal at the deadline of a run whose recorded time box
	// action is auto_close. nil means the pass closes nothing.
	Close func(handle string)
	// AtEnd takes the closing boundary snapshot of a run, compares it with the
	// one taken at launch and returns the verdict (secassess.AuditVerdict) and
	// the time the snapshot was taken. It does git I/O, so only the daemon loop
	// sets it; the runs list never does. nil means no audit is taken here.
	AtEnd func(ctx context.Context, r Run) (verdict string, at time.Time)
	// RetentionDays is the age, in days, after which a run's side data is
	// deleted (0 keeps it as long as the run is recorded). nil reads as 0.
	RetentionDays func() int
}

var reconcileMu sync.Mutex

// errEndingRecorded aborts a mutation when another writer already recorded how
// the run ends.
var errEndingRecorded = errors.New("secassesssvc: the end is already recorded")

// bound reports whether a link's confidence is the launcher's own echo.
func bound(sessionID string, confidence float64) bool {
	return sessionID != "" && confidence >= secassess.BindMinConfidence
}

func isOpen(state string) bool {
	switch secassess.RelaxState(state) {
	case secassess.RelaxPendingBind, secassess.RelaxActive, secassess.RelaxOrgGrant, secassess.RelaxTierOn:
		return true
	}
	return false
}

// openRelax reports whether the run has a relaxation still in force or still
// to be bound.
func openRelax(r Run) bool {
	for _, x := range r.Relax {
		if isOpen(x.State) {
			return true
		}
	}
	return false
}

// watchEnd says the run's kind wants its end recorded (a kind column).
func watchEnd(r Run) bool {
	k, ok := secassess.KindByID(r.Kind)
	return ok && k.WatchEnd
}

// needsPass says the reconcile pass has something to do for the run: it is
// started, its end has not been recorded, and it holds an open relaxation, is
// reported to the org, or is a kind whose end is watched.
func needsPass(r Run) bool {
	return r.IsStarted() && r.Handle != "" && r.EndedAt.IsZero() && (openRelax(r) || r.Reported || watchEnd(r))
}

// onlyWatching says the run is selected by the end watch alone. Such a run is
// skipped when no terminal resolver is injected: a nil resolver reads every
// terminal as gone, which is right for ending a relaxation and wrong for
// stamping an end.
func onlyWatching(r Run) bool { return !openRelax(r) && !r.Reported }

// auditCatchUp is how long after a run ended its closing snapshot is still
// taken; later than that the audit is recorded as could-not-check, never as
// unchanged.
const auditCatchUp = time.Hour

// auditOwed says the run owes a closing boundary audit: it is a kind whose end
// is watched, no verdict is recorded yet (a run launched with the audit off, or
// of a kind that is not audited, records its verdict at launch), and it was
// launched by a build that records a time box (a run recorded before the depth
// work took no launch snapshot and is left alone).
func auditOwed(r Run) bool {
	return r.Audit == "" && r.TimeBoxMinutes > 0 && watchEnd(r)
}

// needsAudit says an ended run still lacks its boundary audit and the pass can
// take it.
func needsAudit(r Run, p Ports) bool {
	return p.AtEnd != nil && r.IsStarted() && !r.EndedAt.IsZero() && auditOwed(r)
}

// Reconcile walks every started run that still has something to do and
// applies the table. It is safe to call from several goroutines (calls are
// serialized) and never returns an error: a failed port call is recorded on
// the relaxation (create_failed, row_changed) and the next pass retries what
// can be retried. It returns how many runs changed.
func Reconcile(ctx context.Context, runs *Store, p Ports) int {
	reconcileMu.Lock()
	defer reconcileMu.Unlock()
	now := time.Now()
	if p.Now != nil {
		now = p.Now()
	}
	// An unreadable record holds no runs to walk and nothing to prune against:
	// leave it, and every stored file, exactly as it is.
	all, err := runs.AllErr()
	if err != nil {
		return 0
	}
	changed := 0
	for _, r := range all {
		if ctx.Err() != nil {
			break
		}
		switch {
		case needsPass(r):
			if onlyWatching(r) && p.Terminal == nil {
				continue
			}
			if reconcileRun(ctx, runs, p, r, now) {
				changed++
			}
		case needsAudit(r, p):
			if catchUpAudit(ctx, runs, p, r, now) {
				changed++
			}
		}
	}
	retention := 0
	if p.RetentionDays != nil {
		retention = p.RetentionDays()
	}
	runs.PruneSide(retention, now)
	return changed
}

// catchUpAudit takes the closing snapshot of a run that ended in an earlier
// pass without one (the runs list's pass has no snapshotter). A run that ended
// longer ago than auditCatchUp is recorded as could-not-check.
func catchUpAudit(ctx context.Context, runs *Store, p Ports, r Run, now time.Time) bool {
	verdict, at := string(secassess.AuditUnchecked), now
	if now.Sub(r.EndedAt) <= auditCatchUp {
		if v, t := p.AtEnd(ctx, r); v != "" {
			verdict, at = v, t
		}
	}
	_, found, _ := runs.Mutate(r.ID, func(cur *Run) error {
		if cur.Audit == "" {
			cur.Audit, cur.AuditAt = verdict, at.UTC()
		}
		return nil
	})
	return found
}

// closeAtDeadline closes the terminal of a run that is over its time box when
// the action recorded on the run is auto_close. It records the reason before it
// closes, so the terminal is closed once and the end reads "time_box".
func closeAtDeadline(runs *Store, p Ports, r Run, pf passFacts) {
	if !pf.live || p.Close == nil || r.TimeBoxAction != secassess.TimeBoxAutoClose || r.EndWhy != "" {
		return
	}
	if !secassess.OverTimeBox(pf.launched, r.TimeBoxMinutes, pf.now) {
		return
	}
	_, found, err := runs.Mutate(r.ID, func(cur *Run) error {
		if cur.EndWhy != "" {
			return errEndingRecorded
		}
		cur.EndWhy = secassess.EndTimeBox
		return nil
	})
	if found && err == nil {
		p.Close(r.Handle)
	}
}

// passFacts is what one reconcile pass knows about one run, read once so every
// relaxation of the run is judged on the same facts.
type passFacts struct {
	live      bool
	sessionID string
	conf      float64
	now       time.Time
	launched  time.Time
	minutes   int
}

func runPassFacts(p Ports, r Run, now time.Time) passFacts {
	pf := passFacts{now: now, launched: r.ConfirmedAt, minutes: r.RelaxMinutes}
	if p.Terminal != nil {
		pf.live, pf.sessionID, pf.conf = p.Terminal(r.Handle)
	}
	if pf.launched.IsZero() {
		pf.launched = r.CreatedAt
	}
	if pf.minutes <= 0 {
		pf.minutes = secassess.ManagedMaxMinutes
	}
	return pf
}

func reconcileRun(ctx context.Context, runs *Store, p Ports, r Run, now time.Time) bool {
	pf := runPassFacts(p, r, now)
	closeAtDeadline(runs, p, r, pf)
	results := make([]Relax, len(r.Relax))
	copy(results, r.Relax)
	dirty := false
	for i := range results {
		if isOpen(results[i].State) && stepRelax(ctx, p, r, &results[i], pf) {
			dirty = true
		}
	}
	end := !pf.live && r.EndedAt.IsZero()
	if !dirty && !end {
		return false
	}
	var rel RelaxedCount
	counted := false
	if end && p.Count != nil {
		rel, counted = countRelaxed(ctx, p, results, pf)
	}
	verdict, auditAt := takeAudit(ctx, p, r, end)
	upd, found, _ := runs.Mutate(r.ID, func(cur *Run) error {
		// Merge by key so a concurrent change to another field (an import
		// record) is never overwritten.
		for i := range cur.Relax {
			for _, nx := range results {
				if nx.Key == cur.Relax[i].Key {
					cur.Relax[i] = nx
				}
			}
		}
		if end {
			cur.EndedAt = now.UTC()
			if cur.EndWhy == "" {
				cur.EndWhy = secassess.EndGone
			}
			if verdict != "" && cur.Audit == "" {
				cur.Audit, cur.AuditAt = verdict, auditAt.UTC()
			}
			if counted {
				cur.Relaxed = &rel
			}
		}
		return nil
	})
	if end && found && r.Reported && p.Event != nil {
		_ = p.Event(ctx, "end", r.ProjectRootHash, firstSession(results), endDetail(upd, results, counted, rel))
	}
	return true
}

// takeAudit takes the closing boundary snapshot on the end transition when
// the pass has a snapshotter and the run is still owed one.
func takeAudit(ctx context.Context, p Ports, r Run, end bool) (verdict string, at time.Time) {
	if !end || p.AtEnd == nil || !auditOwed(r) {
		return "", time.Time{}
	}
	return p.AtEnd(ctx, r)
}

// stepRelax walks one open relaxation through the transition table and applies
// the table's action. It reports whether the relaxation's record changed.
func stepRelax(ctx context.Context, p Ports, r Run, x *Relax, pf passFacts) bool {
	step := secassess.RelaxStep(secassess.StepInput{
		State: secassess.RelaxState(x.State), Route: secassess.Route(x.Route), Now: pf.now,
		LaunchedAt: pf.launched, MaxMinutes: pf.minutes, TerminalLive: pf.live, SessionBound: bound(pf.sessionID, pf.conf),
	})
	dirty := false
	if step.Next != secassess.RelaxState(x.State) {
		x.State = string(step.Next)
		x.EndReason = step.EndReason
		dirty = true
	}
	switch step.Action {
	case secassess.ActionCreate:
		applyCreate(ctx, p, r, x, pf)
		dirty = true
	case secassess.ActionRenew:
		if renewRelax(ctx, p, x, pf) {
			dirty = true
		}
	case secassess.ActionDelete:
		dirty = true
		if p.DeleteApproval != nil {
			if ok, err := p.DeleteApproval(ctx, x.ApprovalID, x.GrantedBy, x.ExpiresAt); err == nil && !ok {
				x.Note = "row_changed"
			}
		}
	}
	return dirty
}

// renewRelax pushes the approval's expiry out. A failed renewal is left for
// the next pass (the short expiry bounds it); a row someone else changed or
// removed is recorded lost. It reports whether the record changed.
func renewRelax(ctx context.Context, p Ports, x *Relax, pf passFacts) bool {
	if p.RenewApproval == nil {
		return false
	}
	exp := secassess.RenewExpiry(pf.now, pf.launched, pf.minutes).UTC().Truncate(time.Second)
	ok, err := p.RenewApproval(ctx, x.ApprovalID, x.GrantedBy, x.ExpiresAt, exp)
	switch {
	case err != nil:
		return false
	case ok:
		x.ExpiresAt = exp
	default:
		x.State, x.Note = string(secassess.RelaxLost), "row_changed"
	}
	return true
}

// countRelaxed counts the verdicts the run's local relaxations changed over its
// lifetime, for the end row. counted is false when nothing could be counted.
func countRelaxed(ctx context.Context, p Ports, results []Relax, pf passFacts) (rel RelaxedCount, counted bool) {
	rules, sessions, by := relaxedKeys(results)
	if len(rules) == 0 {
		return rel, false
	}
	ex, ap, err := p.Count(ctx, by, sessions, rules, pf.launched, pf.now)
	if err != nil {
		return rel, false
	}
	return RelaxedCount{Exact: ex, Approx: ap}, true
}

// applyCreate makes the session-scoped approval row once the session is
// bound, and records what happened.
func applyCreate(ctx context.Context, p Ports, r Run, x *Relax, pf passFacts) {
	if p.CreateApproval == nil {
		x.State, x.Note = string(secassess.RelaxFailed), "create_failed"
		return
	}
	exp := secassess.RenewExpiry(pf.now, pf.launched, pf.minutes).UTC().Truncate(time.Second)
	id, created, err := p.CreateApproval(ctx, x.Key, secassess.ScopeSession, pf.sessionID, r.ProjectRootHash, x.GrantedBy, exp)
	switch {
	case err != nil:
		x.State, x.Note = string(secassess.RelaxFailed), "create_failed"
	case !created:
		x.State, x.Note = string(secassess.RelaxExisting), "existing_row"
	default:
		x.ApprovalID, x.ExpiresAt, x.SessionID = id, exp, pf.sessionID
	}
}

// relaxedKeys returns the rule ids of the run's local relaxations, the
// sessions they bound to and the grantor to count under.
func relaxedKeys(rs []Relax) (rules, sessions []string, grantedBy string) {
	seen := map[string]bool{}
	for _, x := range rs {
		if x.Type != string(secassess.RelaxRule) {
			continue
		}
		rules = append(rules, x.Key)
		if x.SessionID != "" && !seen[x.SessionID] {
			seen[x.SessionID] = true
			sessions = append(sessions, x.SessionID)
		}
		if x.GrantedBy != "" {
			grantedBy = x.GrantedBy
		}
	}
	return rules, sessions, grantedBy
}

func firstSession(rs []Relax) string {
	for _, x := range rs {
		if x.SessionID != "" {
			return x.SessionID
		}
	}
	return ""
}

// endDetail is the content-free line of the `end` audit row: the run id, how
// each relaxation ended and the counts.
func endDetail(r Run, rs []Relax, counted bool, c RelaxedCount) string {
	var b strings.Builder
	b.WriteString("run " + r.ID + " kind " + r.Kind)
	if r.EndWhy != "" {
		b.WriteString("; ended " + r.EndWhy)
	}
	if r.Audit != "" {
		b.WriteString("; boundary audit " + r.Audit)
	}
	for _, x := range rs {
		b.WriteString("; " + x.Key + " " + x.State)
		if x.EndReason != "" {
			b.WriteString(" (" + x.EndReason + ")")
		}
		if x.Note != "" {
			b.WriteString(" [" + x.Note + "]")
		}
	}
	if counted {
		b.WriteString("; verdicts changed " + strconv.Itoa(c.Exact) + " exact, " + strconv.Itoa(c.Approx) + " approx")
	}
	return b.String()
}
