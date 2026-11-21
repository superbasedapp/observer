//go:build !sbo_omit_terminals

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/toolinstall"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// toolInstallLedger is the cmd-side dashapi.ToolInstallLedger: the node's
// record of guided installs the dashboard ran (tool_installs, agent migration
// 148, written ONLY through internal/store/toolinstalls.go) plus the exit
// tracking that settles each record, and the uninstall built from it.
//
// Decisions are delegated, never re-implemented here: the lifecycle
// (installing -> installed ...) is internal/toolinstall's transition table,
// and the uninstall argv is internal/toolinstall.PlanUninstall over the argv
// the install ACTUALLY ran (recorded verbatim). This file only does the I/O:
// the store calls, the PTY exit wiring and the post-run binary re-check.
//
// Exit tracking: the terminal stack's ONE termsession OnExit closure calls
// observeExit for every session; a handle this ledger registered settles its
// record. The pre-registration window (a setup PTY that exits before track
// runs) is closed the way termsvc closes it — track reconciles against the
// manager's authoritative ExitStatus right after registering — and the
// pending map makes settlement exactly-once whichever path gets there first.
//
// A record left in an in-flight status by a PREVIOUS daemon (no live process
// here tracks it) is settled as interrupted lazily, on the next read.
type toolInstallLedger struct {
	st     *store.Store
	logger *slog.Logger
	now    func() time.Time
	// planFor re-derives the install plan for a tool — the same plan the
	// install route ran — so the record can store its channel.
	planFor func(tool string) (dashboardInstallPlan, bool)
	// resolveBin re-checks where the tool's binary resolves after a run
	// settles ("" = not found).
	resolveBin func(tool string) string
	// lookArgv0 re-resolves a recorded absolute program that no longer
	// exists (a node version switch) by its base name.
	lookArgv0 installArgv0Lookup
	// onInstalled, when set, runs once an install settles as installed with
	// its binary resolving (attach_standalone.go wires the post-install hook
	// registration here).
	onInstalled func(tool string)
	// onSandboxSettled, when set, runs once a sandbox record settles (any
	// status), with the record's backend.
	onSandboxSettled func(backend string)
	// bootAt is when this ledger (this daemon process) started. Only an
	// in-flight phase that began BEFORE it can be an orphan of a previous
	// daemon; a phase this process began is always settled by this process
	// (track handles even an already-reaped handle), so the lazy sweep never
	// races a just-inserted row that track has not registered yet.
	bootAt time.Time
	// daemonListening is set on a ledger a CLI process opens (nil: this
	// process is the daemon, the owner of every record it did not begin).
	// It reports whether a daemon listens now; while one does, the CLI never
	// settles a record that daemon may own (orphanRules).
	daemonListening func(ctx context.Context) bool

	mu sync.Mutex
	// exitStatus is the PTY manager's authoritative exit status. Set once the
	// manager exists (the manager's OnExit closure is built before it).
	exitStatus func(handle string) (exited bool, code int, ok bool)
	// pending: setup handle -> the record it settles.
	pending map[string]pendingToolInstallOp
	// tracked: record ids a live PTY in THIS process will settle.
	tracked map[int64]bool
}

type pendingToolInstallOp struct {
	id   int64
	tool string
	from toolinstall.Status
	// subject is the record's subject_kind ("" reads as store.SubjectTool).
	subject string
	// verify, set on a sandbox record, re-checks the prerequisite after the
	// run (its own passive Detect, or for a step only the active check can
	// see, that check after an exit 0; sandboxSettleRules) and returns where
	// it resolved ("" = not found); exitOK says the run exited 0. A tool
	// record re-resolves its binary.
	verify func(exitOK bool) string
}

// subjectOf is op's subject_kind.
func (op pendingToolInstallOp) subjectOf() string {
	if op.subject == "" {
		return store.SubjectTool
	}
	return op.subject
}

// newToolInstallLedger builds the production ledger over st.
func newToolInstallLedger(st *store.Store, logger *slog.Logger) *toolInstallLedger {
	if logger == nil {
		logger = slog.Default()
	}
	return &toolInstallLedger{
		st:         st,
		logger:     logger,
		now:        time.Now,
		planFor:    dashboardInstallPlanForTool,
		resolveBin: installedBinFor,
		lookArgv0:  dashInstallArgv0,
		bootAt:     time.Now(),
		pending:    map[string]pendingToolInstallOp{},
		tracked:    map[int64]bool{},
	}
}

// newToolInstallLedgerFor returns the ledger over database, or nil when no
// database is wired (every method below is nil-receiver safe where the
// terminal stack calls it unconditionally).
func newToolInstallLedgerFor(database *sql.DB, logger *slog.Logger) *toolInstallLedger {
	if database == nil {
		return nil
	}
	return newToolInstallLedger(store.New(database), logger)
}

// setExitStatus wires the manager's exit-status reader. Nil-safe.
func (l *toolInstallLedger) setExitStatus(fn func(handle string) (bool, int, bool)) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.exitStatus = fn
	l.mu.Unlock()
}

// setOnSandboxSettled wires the callback run after a sandbox record
// settles. Nil-safe.
func (l *toolInstallLedger) setOnSandboxSettled(fn func(backend string)) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.onSandboxSettled = fn
	l.mu.Unlock()
}

// sandboxSettled runs onSandboxSettled for record id, with its backend read
// back from the record ("" when it cannot be read).
func (l *toolInstallLedger) sandboxSettled(id int64) {
	l.mu.Lock()
	fn := l.onSandboxSettled
	l.mu.Unlock()
	if fn == nil {
		return
	}
	backend := ""
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if row, ok, err := l.st.GetInstallRecord(ctx, store.SubjectSandbox, id); err == nil && ok {
		backend = row.Backend
	}
	fn(backend)
}

// setOnInstalled wires the post-install callback. Nil-safe.
func (l *toolInstallLedger) setOnInstalled(fn func(tool string)) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.onInstalled = fn
	l.mu.Unlock()
}

// dashboardInstallPlanForTool is the SAME plan toolInstallHintSeam hands the
// install route (one lookup ladder, one selection rule).
func dashboardInstallPlanForTool(tool string) (dashboardInstallPlan, bool) {
	installs, ok := installHintsFor(tool)
	if !ok {
		return dashboardInstallPlan{}, false
	}
	return dashboardInstallPlanFor(installs, runtime.GOOS, dashboardInstallHome(), dashInstallArgv0)
}

// installedBinFor re-runs the registry resolution ladder for a tool (terminal
// row first, then GUI row) and returns the resolved binary, or "".
func installedBinFor(tool string) string {
	env := dashResolveEnv()
	if ic, ok := integration.For(tool); ok && ic.Binary != nil {
		if r := toolresolve.Resolve(*ic.Binary, env); guiPreflightLaunchable[r.Verdict] {
			return r.Bin
		}
		return ""
	}
	if g, ok := integration.GUILaunchFor(tool); ok {
		if r := toolresolve.ResolveGUI(g.Spec, env); guiPreflightLaunchable[r.Verdict] {
			return r.Bin
		}
	}
	return ""
}

// RecordInstall implements dashapi.ToolInstallLedger.
func (l *toolInstallLedger) RecordInstall(ctx context.Context, tool, handle string, argv []string, display string) error {
	plan, ok := l.planFor(tool)
	if !ok || plan.Channel == "" {
		return fmt.Errorf("toolInstallLedger.RecordInstall: no install plan for %q", tool)
	}
	id, err := l.st.InsertToolInstall(ctx, store.ToolInstallRow{
		Tool:      tool,
		Channel:   plan.Channel,
		Package:   toolinstall.PackageOf(plan.Channel, argv),
		Argv:      argv,
		Display:   display,
		Status:    string(toolinstall.StatusInstalling),
		StartedAt: l.now(),
	})
	if err != nil {
		return fmt.Errorf("toolInstallLedger.RecordInstall: %w", err)
	}
	l.track(handle, pendingToolInstallOp{id: id, tool: tool, from: toolinstall.StatusInstalling})
	return nil
}

// track registers handle as settling op, then reconciles against the
// manager's exit status so an exit that fired before registration is not
// lost.
func (l *toolInstallLedger) track(handle string, op pendingToolInstallOp) {
	l.mu.Lock()
	l.pending[handle] = op
	l.tracked[op.id] = true
	status := l.exitStatus
	l.mu.Unlock()
	if status == nil {
		return
	}
	exited, code, known := status(handle)
	switch {
	case !known:
		// The handle is already gone: its exit was never observed here.
		l.settle(handle, toolinstall.EventOrphaned, 0)
	case exited:
		l.settle(handle, toolinstall.ExitEvent(code), code)
	}
}

// observeExit is called from the terminal stack's OnExit closure for EVERY
// PTY session; only handles this ledger registered settle anything.
func (l *toolInstallLedger) observeExit(handle string, code int) {
	if l == nil {
		return
	}
	l.settle(handle, toolinstall.ExitEvent(code), code)
}

// liveHandle returns the PTY handle a live install / uninstall of record id
// runs in ("" when no PTY in this process tracks it).
func (l *toolInstallLedger) liveHandle(id int64) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	for h, op := range l.pending {
		if op.id == id {
			return h
		}
	}
	return ""
}

// liveRecord renders row and adds what only this process knows: the live
// terminal handle and whether the run may be waiting for input (T-034j).
func (l *toolInstallLedger) liveRecord(row store.ToolInstallRow) dashapi.ToolInstallRecord {
	rec := toToolInstallRecord(row)
	st := toolinstall.Status(row.Status)
	if !toolinstall.InFlight(st) {
		return rec
	}
	rec.TerminalHandle = l.liveHandle(row.ID)
	phaseStart := row.StartedAt
	if st == toolinstall.StatusUninstalling && row.UninstallStartedAt != nil {
		phaseStart = *row.UninstallStartedAt
	}
	rec.MaybeWaitingForInput = toolinstall.MaybeWaitingForInput(st, phaseStart, l.now())
	return rec
}

// settle applies ev to the record handle tracks — exactly once.
func (l *toolInstallLedger) settle(handle string, ev toolinstall.Event, code int) {
	l.mu.Lock()
	op, ok := l.pending[handle]
	if ok {
		delete(l.pending, handle)
		delete(l.tracked, op.id)
	}
	l.mu.Unlock()
	if !ok {
		return
	}
	to, allowed := toolinstall.Next(op.from, ev)
	if !allowed {
		return
	}
	finish := store.ToolInstallFinish{Status: string(to), ExitCode: code, At: l.now()}
	switch {
	case ev == toolinstall.EventOrphaned:
	case op.verify != nil:
		// A sandbox step is "installed" only when its prerequisite reads
		// present afterwards (plan section 3.5), never the tool path. The
		// check may run the row's probe, so the store's deadline starts
		// after it.
		finish.ResolvedBin = op.verify(ev == toolinstall.EventExitOK)
	case op.subjectOf() == store.SubjectTool && l.resolveBin != nil:
		finish.ResolvedBin = l.resolveBin(op.tool)
	}
	// An install that exited 0 is "installed" only when its binary resolves
	// afterwards; otherwise it is its own outcome (T-034j).
	if op.from == toolinstall.StatusInstalling && ev == toolinstall.EventExitOK {
		ev = toolinstall.InstallExitEvent(code, finish.ResolvedBin != "")
		if to, allowed = toolinstall.Next(op.from, ev); !allowed {
			return
		}
		finish.Status = string(to)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var (
		done bool
		err  error
	)
	if op.from == toolinstall.StatusInstalling {
		done, err = l.st.FinishInstallRecord(ctx, op.subjectOf(), op.id, string(op.from), finish)
	} else {
		done, err = l.st.FinishUninstallRecord(ctx, op.subjectOf(), op.id, string(op.from), finish)
	}
	if err != nil {
		l.logger.Warn("tool install ledger: settling record failed", "tool", op.tool, "subject", op.subjectOf(), "id", op.id, "err", err)
		return
	}
	if !done {
		// The compare-and-set lost: the record left op.from before this
		// exit landed (another process settled it). Say so, never "settled".
		l.logger.Warn("tool install ledger: record was already settled elsewhere", "tool", op.tool, "subject", op.subjectOf(), "id", op.id, "want", to)
		return
	}
	l.logger.Info("tool install ledger: record settled", "tool", op.tool, "subject", op.subjectOf(), "id", op.id, "status", to, "exit_code", code, "resolved_bin", finish.ResolvedBin)
	if op.subjectOf() == store.SubjectSandbox {
		l.sandboxSettled(op.id)
	}
	if to == toolinstall.StatusInstalled && finish.ResolvedBin != "" && op.subjectOf() == store.SubjectTool {
		l.mu.Lock()
		fn := l.onInstalled
		l.mu.Unlock()
		if fn != nil {
			fn(op.tool)
		}
	}
}

// orphanCtx is what the orphan rules read about one record.
type orphanCtx struct {
	inFlight bool
	// begunHere: the record's phase began after this process started.
	begunHere bool
	// trackedHere: a live PTY in this process settles it.
	trackedHere bool
	// isDaemon: this process is the daemon (no daemonListening seam).
	isDaemon bool
	// daemonListening: a CLI process found a daemon listening (read only
	// when the rows above it did not decide).
	daemonListening func() bool
}

// orphanRule is one row of the ordered orphan table, walked top-down; the
// first row that decides answers whether to settle the record as
// interrupted.
type orphanRule struct {
	name  string
	match func(c orphanCtx) (settle, hit bool)
}

// orphanRules decide whether a record is an orphan this process may settle.
// Only the process that owns a record settles it: the daemon owns every
// record begun before it started that nothing here tracks (the daemon that
// began it is gone); a CLI process never settles a record a live daemon may
// own (a setup terminal the daemon started), only one left when no daemon
// listens at all.
var orphanRules = []orphanRule{
	{"not_in_flight", func(c orphanCtx) (bool, bool) { return false, !c.inFlight }},
	{"begun_here", func(c orphanCtx) (bool, bool) { return false, c.begunHere }},
	{"tracked_here", func(c orphanCtx) (bool, bool) { return false, c.trackedHere }},
	{"daemon_owns_it", func(c orphanCtx) (bool, bool) { return true, c.isDaemon }},
	{"daemon_listening", func(c orphanCtx) (bool, bool) { return false, c.daemonListening() }},
	{"no_daemon", func(orphanCtx) (bool, bool) { return true, true }},
}

// orphanDecision walks orphanRules for c and returns the answer and the row
// that decided it.
func orphanDecision(c orphanCtx) (bool, string) {
	for _, r := range orphanRules {
		if settle, hit := r.match(c); hit {
			return settle, r.name
		}
	}
	return false, ""
}

// reconcileOrphan settles an in-flight row this process may settle (see
// orphanRules) and returns the row as it now stands.
func (l *toolInstallLedger) reconcileOrphan(ctx context.Context, row store.ToolInstallRow) store.ToolInstallRow {
	st := toolinstall.Status(row.Status)
	phaseStart := row.StartedAt
	if st == toolinstall.StatusUninstalling {
		phaseStart = time.Time{}
		if row.UninstallStartedAt != nil {
			phaseStart = *row.UninstallStartedAt
		}
	}
	l.mu.Lock()
	live := l.tracked[row.ID]
	l.mu.Unlock()
	settle, _ := orphanDecision(orphanCtx{
		inFlight:    toolinstall.InFlight(st),
		begunHere:   !phaseStart.Before(l.bootAt),
		trackedHere: live,
		isDaemon:    l.daemonListening == nil,
		daemonListening: func() bool {
			return l.daemonListening(ctx)
		},
	})
	if !settle {
		return row
	}
	to, ok := toolinstall.Next(st, toolinstall.EventOrphaned)
	if !ok {
		return row
	}
	subject := row.SubjectKind
	if subject == "" {
		subject = store.SubjectTool
	}
	if done, err := l.st.SetInstallRecordStatus(ctx, subject, row.ID, row.Status, string(to)); err == nil && done {
		row.Status = string(to)
	} else if err == nil {
		// Lost the CAS to a concurrent settle: re-read.
		if fresh, found, err := l.st.GetInstallRecord(ctx, subject, row.ID); err == nil && found {
			return fresh
		}
	}
	return row
}

// toRecord renders a row for the wire, resolving every capability through
// internal/toolinstall (never a channel or tool name branch here).
func toToolInstallRecord(row store.ToolInstallRow) dashapi.ToolInstallRecord {
	st := toolinstall.Status(row.Status)
	rec := dashapi.ToolInstallRecord{
		ID:                 row.ID,
		Tool:               row.Tool,
		Channel:            row.Channel,
		Package:            row.Package,
		Command:            row.Display,
		Status:             row.Status,
		ExitCode:           row.ExitCode,
		InstalledAt:        row.StartedAt,
		FinishedAt:         row.FinishedAt,
		ResolvedBin:        row.ResolvedBin,
		CanForget:          toolinstall.Forgettable(st),
		UninstallStartedAt: row.UninstallStartedAt,
		UninstalledAt:      row.UninstallFinishedAt,
		UninstallExitCode:  row.UninstallExitCode,
		SubjectKind:        wireSubject(row.SubjectKind),
		Backend:            row.Backend,
		Source:             row.Source,
		Digest:             row.Digest,
		PlacedPath:         row.PlacedPath,
		Elevated:           row.Elevated,
	}
	if toolinstall.HasDefinedUninstall(row.Channel) {
		if plan, err := toolinstall.PlanUninstall(row.Channel, row.Argv); err == nil {
			rec.UninstallCommand = plan.Display
			rec.CanUninstall = toolinstall.Uninstallable(st)
		} else {
			rec.UninstallGuidance = toolinstall.NoDefinedUninstallGuidance
		}
	} else {
		rec.UninstallGuidance = toolinstall.GuidanceFor(row.Channel)
	}
	if row.UninstallDisplay != "" {
		rec.UninstallCommand = row.UninstallDisplay
	}
	return rec
}

// Lookup implements dashapi.ToolInstallLedger.
func (l *toolInstallLedger) Lookup(ctx context.Context, tool string) (dashapi.ToolInstallRecord, bool, error) {
	row, ok, err := l.st.LatestToolInstall(ctx, tool)
	if err != nil || !ok {
		return dashapi.ToolInstallRecord{}, ok, err
	}
	return l.liveRecord(l.reconcileOrphan(ctx, row)), true, nil
}

// List implements dashapi.ToolInstallLedger.
func (l *toolInstallLedger) List(ctx context.Context) ([]dashapi.ToolInstallRecord, error) {
	rows, err := l.st.ListLatestToolInstalls(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]dashapi.ToolInstallRecord, 0, len(rows))
	for _, row := range rows {
		out = append(out, l.liveRecord(l.reconcileOrphan(ctx, row)))
	}
	return out, nil
}

// latestFor loads the record the operator confirmed: it must be tool's latest
// not-forgotten record.
func (l *toolInstallLedger) latestFor(ctx context.Context, tool string, id int64) (store.ToolInstallRow, error) {
	row, ok, err := l.st.LatestToolInstall(ctx, tool)
	if err != nil {
		return store.ToolInstallRow{}, err
	}
	if !ok {
		return store.ToolInstallRow{}, dashapi.ErrToolInstallNotFound
	}
	if row.ID != id {
		return store.ToolInstallRow{}, dashapi.ErrToolInstallStale
	}
	return l.reconcileOrphan(ctx, row), nil
}

// Uninstall implements dashapi.ToolInstallLedger.
func (l *toolInstallLedger) Uninstall(ctx context.Context, tool string, id int64, spawn func(argv []string) (string, error)) (dashapi.ToolUninstallStarted, error) {
	row, err := l.latestFor(ctx, tool, id)
	if err != nil {
		return dashapi.ToolUninstallStarted{}, err
	}
	plan, err := toolinstall.PlanUninstall(row.Channel, row.Argv)
	if err != nil {
		guidance := toolinstall.GuidanceFor(row.Channel)
		if guidance == "" {
			guidance = toolinstall.NoDefinedUninstallGuidance
		}
		return dashapi.ToolUninstallStarted{}, fmt.Errorf("%w: %s", dashapi.ErrToolUninstallUnsupported, guidance)
	}
	if !toolinstall.Uninstallable(toolinstall.Status(row.Status)) {
		return dashapi.ToolUninstallStarted{}, dashapi.ErrToolInstallStale
	}
	argv := append([]string(nil), plan.Argv...)
	argv[0] = l.liveProgram(argv[0])
	from := toolinstall.UninstallableFrom()
	fromStr := make([]string, len(from))
	for i, s := range from {
		fromStr[i] = string(s)
	}
	prev, claimed, err := l.st.ClaimToolUninstall(ctx, id, fromStr, string(toolinstall.StatusUninstalling), argv, plan.Display, l.now())
	if err != nil {
		return dashapi.ToolUninstallStarted{}, err
	}
	if !claimed {
		return dashapi.ToolUninstallStarted{}, dashapi.ErrToolInstallStale
	}
	handle, err := spawn(argv)
	if err != nil {
		rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, rerr := l.st.RevertToolUninstall(rctx, id, string(toolinstall.StatusUninstalling), prev); rerr != nil {
			l.logger.Warn("tool install ledger: reverting a failed uninstall claim failed", "tool", tool, "id", id, "err", rerr)
		}
		return dashapi.ToolUninstallStarted{}, err
	}
	l.track(handle, pendingToolInstallOp{id: id, tool: tool, from: toolinstall.StatusUninstalling})
	return dashapi.ToolUninstallStarted{RecordID: id, Handle: handle, Tool: tool, Command: plan.Display, Package: plan.Package}, nil
}

// liveProgram keeps the recorded program when it still exists, else
// re-resolves it by base name on the merged PATH (an nvm switch can move
// npm), else falls back to the bare name for the spawner's own PATH lookup.
func (l *toolInstallLedger) liveProgram(prog string) string {
	if !filepath.IsAbs(prog) {
		return prog
	}
	if fi, err := os.Stat(prog); err == nil && fi.Mode().IsRegular() {
		return prog
	}
	base := filepath.Base(prog)
	if l.lookArgv0 != nil {
		if abs, ok := l.lookArgv0(base); ok {
			return abs
		}
	}
	return base
}

// Forget implements dashapi.ToolInstallLedger.
func (l *toolInstallLedger) Forget(ctx context.Context, tool string, id int64) error {
	row, err := l.latestFor(ctx, tool, id)
	if err != nil {
		return err
	}
	if !toolinstall.Forgettable(toolinstall.Status(row.Status)) {
		return dashapi.ErrToolInstallStale
	}
	from := toolinstall.ForgettableFrom()
	fromStr := make([]string, len(from))
	for i, s := range from {
		fromStr[i] = string(s)
	}
	ok, err := l.st.ForgetToolInstall(ctx, id, fromStr, l.now())
	if err != nil {
		return err
	}
	if !ok {
		return dashapi.ErrToolInstallStale
	}
	return nil
}

// Compile-time check.
var _ dashapi.ToolInstallLedger = (*toolInstallLedger)(nil)

// wireSubject is the record's subject on the wire: "" for an AI tool (the
// default every tool route already reads), the subject otherwise, so a tool
// record's JSON is exactly what it was before migration 222.
func wireSubject(s string) string {
	if s == store.SubjectTool {
		return ""
	}
	return s
}

// ---- sandbox setup records (plan section 3.5, subject_kind sandbox) --------

// sandboxInstallRecord is one sandbox setup step about to be recorded. Name
// is the record's tool column: the prerequisite id (a shared prerequisite
// keeps one record whichever row set it up), or the per-backend name of a
// generic step (sandboxRecordName).
type sandboxInstallRecord struct {
	Name    string
	Backend string
	// Channel is the record's channel: the package manager's channel for a
	// pm step (toolinstall.InstallArgvFor's), the sandboxsetup Channel for
	// every other step.
	Channel string
	Argv    []string
	Display string
	// Source is where a placed file came from (vendor_release, org_mirror,
	// from_file).
	Source   string
	Elevated bool
}

// row turns rec into the store row it inserts, in status installing.
func (l *toolInstallLedger) sandboxRow(rec sandboxInstallRecord) store.ToolInstallRow {
	return store.ToolInstallRow{
		SubjectKind: store.SubjectSandbox,
		Tool:        rec.Name,
		Channel:     rec.Channel,
		Package:     toolinstall.PackageOf(rec.Channel, rec.Argv),
		Argv:        rec.Argv,
		Display:     rec.Display,
		Status:      string(toolinstall.StatusInstalling),
		StartedAt:   l.now(),
		Backend:     rec.Backend,
		Source:      rec.Source,
		Elevated:    rec.Elevated,
	}
}

// RecordSandboxInstall records a sandbox step a setup terminal just started
// (handle is its PTY) and tracks its exit: settle then calls verify (the
// prerequisite read again, sandboxSettleRules) so "installed" means the
// prerequisite is present afterwards, else installed_not_found.
func (l *toolInstallLedger) RecordSandboxInstall(ctx context.Context, rec sandboxInstallRecord, handle string, verify func(exitOK bool) string) (int64, error) {
	if l == nil {
		return 0, errors.New("toolInstallLedger.RecordSandboxInstall: no install ledger in this daemon")
	}
	id, err := l.st.InsertToolInstall(ctx, l.sandboxRow(rec))
	if err != nil {
		return 0, fmt.Errorf("toolInstallLedger.RecordSandboxInstall: %w", err)
	}
	l.track(handle, pendingToolInstallOp{id: id, tool: rec.Name, from: toolinstall.StatusInstalling, subject: store.SubjectSandbox, verify: verify})
	return id, nil
}

// SettleSandboxForeground settles a sandbox step that ran in the foreground
// on the person's own terminal (the CLI surface: no PTY handle) with its exit
// code.
func (l *toolInstallLedger) SettleSandboxForeground(ctx context.Context, rec sandboxInstallRecord, code int, verify func(exitOK bool) string) (int64, error) {
	if l == nil {
		return 0, errors.New("toolInstallLedger.SettleSandboxForeground: no install ledger in this process")
	}
	id, err := l.st.InsertToolInstall(ctx, l.sandboxRow(rec))
	if err != nil {
		return 0, fmt.Errorf("toolInstallLedger.SettleSandboxForeground: %w", err)
	}
	handle := fmt.Sprintf("sandbox-foreground-%d", id)
	l.mu.Lock()
	l.pending[handle] = pendingToolInstallOp{id: id, tool: rec.Name, from: toolinstall.StatusInstalling, subject: store.SubjectSandbox, verify: verify}
	l.tracked[id] = true
	l.mu.Unlock()
	l.settle(handle, toolinstall.ExitEvent(code), code)
	return id, nil
}

// BeginSandboxOp records an in-process sandbox step (a pinned download, a
// content fetch) that an op, not a PTY, drives. The record is tracked by
// this process until FinishSandboxOp settles it, so the orphan sweep never
// takes it; a daemon restart leaves it in flight and reconcileOrphan marks
// it interrupted.
func (l *toolInstallLedger) BeginSandboxOp(ctx context.Context, rec sandboxInstallRecord) (int64, error) {
	if l == nil {
		return 0, errors.New("toolInstallLedger.BeginSandboxOp: no install ledger in this process")
	}
	id, err := l.st.InsertToolInstall(ctx, l.sandboxRow(rec))
	if err != nil {
		return 0, fmt.Errorf("toolInstallLedger.BeginSandboxOp: %w", err)
	}
	l.mu.Lock()
	l.tracked[id] = true
	l.mu.Unlock()
	return id, nil
}

// sandboxOpOutcome is how an in-process sandbox op ended.
type sandboxOpOutcome struct {
	// Err is the op's failure (nil: it finished).
	Err error
	// Digest and PlacedPath are what a pinned download placed.
	Digest, PlacedPath string
}

// FinishSandboxOp settles the record BeginSandboxOp made, from the op's own
// outcome (never a PTY exit): a failure is install_failed; a finished op is
// installed when verify finds the prerequisite afterwards, else
// installed_not_found.
func (l *toolInstallLedger) FinishSandboxOp(ctx context.Context, id int64, out sandboxOpOutcome, verify func() string) (toolinstall.Status, error) {
	if l == nil {
		return "", errors.New("toolInstallLedger.FinishSandboxOp: no install ledger in this process")
	}
	l.mu.Lock()
	delete(l.tracked, id)
	l.mu.Unlock()
	code, found := 0, ""
	if out.Err != nil {
		code = 1
	} else if verify != nil {
		found = verify()
	}
	to, ok := toolinstall.Next(toolinstall.StatusInstalling, toolinstall.InstallExitEvent(code, found != ""))
	if !ok {
		return "", fmt.Errorf("toolInstallLedger.FinishSandboxOp: no transition for record %d", id)
	}
	done, err := l.st.FinishInstallRecord(ctx, store.SubjectSandbox, id, string(toolinstall.StatusInstalling),
		store.ToolInstallFinish{Status: string(to), ExitCode: code, ResolvedBin: found, At: l.now(), Digest: out.Digest, PlacedPath: out.PlacedPath})
	if err != nil {
		return "", fmt.Errorf("toolInstallLedger.FinishSandboxOp: %w", err)
	}
	if !done {
		return "", dashapi.ErrToolInstallStale
	}
	l.logger.Info("tool install ledger: sandbox op settled", "id", id, "status", to, "resolved", found)
	l.sandboxSettled(id)
	return to, nil
}

// SandboxRecords returns the latest sandbox record per name, newest first,
// with an orphaned in-flight record settled as interrupted.
func (l *toolInstallLedger) SandboxRecords(ctx context.Context) ([]store.ToolInstallRow, error) {
	if l == nil {
		return nil, nil
	}
	rows, err := l.st.ListLatestInstallRecords(ctx, store.SubjectSandbox)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		rows[i] = l.reconcileOrphan(ctx, rows[i])
	}
	return rows, nil
}

// SandboxRecordWire renders a sandbox row for the wire (the same rendering
// the tool routes use, plus the live terminal handle).
func (l *toolInstallLedger) SandboxRecordWire(row store.ToolInstallRow) dashapi.ToolInstallRecord {
	return l.liveRecord(row)
}

// latestSandbox loads the sandbox record the person confirmed: it must be
// name's latest not-forgotten record.
func (l *toolInstallLedger) latestSandbox(ctx context.Context, name string, id int64) (store.ToolInstallRow, error) {
	row, ok, err := l.st.LatestInstallRecord(ctx, store.SubjectSandbox, name)
	if err != nil {
		return store.ToolInstallRow{}, err
	}
	if !ok {
		return store.ToolInstallRow{}, dashapi.ErrToolInstallNotFound
	}
	if row.ID != id {
		return store.ToolInstallRow{}, dashapi.ErrToolInstallStale
	}
	return l.reconcileOrphan(ctx, row), nil
}

// uninstallFrom is the uninstallable status set as strings.
func uninstallFrom() []string {
	from := toolinstall.UninstallableFrom()
	out := make([]string, len(from))
	for i, s := range from {
		out[i] = string(s)
	}
	return out
}

// UninstallSandbox claims a sandbox record installed through a package
// channel, derives its uninstall argv with toolinstall.PlanUninstall over the
// argv the install ACTUALLY ran (so an install under sudo is removed under
// sudo, `remove` never `purge`), spawns it through spawn and tracks its exit.
func (l *toolInstallLedger) UninstallSandbox(ctx context.Context, name string, id int64, spawn func(argv []string) (string, error)) (dashapi.ToolUninstallStarted, error) {
	if l == nil {
		return dashapi.ToolUninstallStarted{}, errors.New("toolInstallLedger.UninstallSandbox: no install ledger in this process")
	}
	row, err := l.latestSandbox(ctx, name, id)
	if err != nil {
		return dashapi.ToolUninstallStarted{}, err
	}
	plan, err := toolinstall.PlanUninstall(row.Channel, row.Argv)
	if err != nil {
		return dashapi.ToolUninstallStarted{}, fmt.Errorf("%w: %s", dashapi.ErrToolUninstallUnsupported, toolinstall.NoDefinedUninstallGuidance)
	}
	if !toolinstall.Uninstallable(toolinstall.Status(row.Status)) {
		return dashapi.ToolUninstallStarted{}, dashapi.ErrToolInstallStale
	}
	argv := append([]string(nil), plan.Argv...)
	prev, claimed, err := l.st.ClaimUninstallRecord(ctx, store.SubjectSandbox, id, uninstallFrom(), string(toolinstall.StatusUninstalling), argv, plan.Display, l.now())
	if err != nil {
		return dashapi.ToolUninstallStarted{}, err
	}
	if !claimed {
		return dashapi.ToolUninstallStarted{}, dashapi.ErrToolInstallStale
	}
	handle, err := spawn(argv)
	if err != nil {
		rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, rerr := l.st.RevertUninstallRecord(rctx, store.SubjectSandbox, id, string(toolinstall.StatusUninstalling), prev); rerr != nil {
			l.logger.Warn("tool install ledger: reverting a failed sandbox uninstall claim failed", "name", name, "id", id, "err", rerr)
		}
		return dashapi.ToolUninstallStarted{}, err
	}
	op := pendingToolInstallOp{id: id, tool: name, from: toolinstall.StatusUninstalling, subject: store.SubjectSandbox}
	if handle == "" {
		// A foreground run (the CLI): spawn already returned; its exit code
		// is reported through SettleSandboxUninstall.
		l.mu.Lock()
		l.tracked[id] = true
		l.mu.Unlock()
		return dashapi.ToolUninstallStarted{RecordID: id, Tool: name, Command: plan.Display, Package: plan.Package}, nil
	}
	l.track(handle, op)
	return dashapi.ToolUninstallStarted{RecordID: id, Handle: handle, Tool: name, Command: plan.Display, Package: plan.Package}, nil
}

// SettleSandboxUninstall settles a foreground sandbox uninstall (the CLI)
// with its exit code.
func (l *toolInstallLedger) SettleSandboxUninstall(_ context.Context, name string, id int64, code int) error {
	if l == nil {
		return errors.New("toolInstallLedger.SettleSandboxUninstall: no install ledger in this process")
	}
	handle := fmt.Sprintf("sandbox-foreground-uninstall-%d", id)
	l.mu.Lock()
	l.pending[handle] = pendingToolInstallOp{id: id, tool: name, from: toolinstall.StatusUninstalling, subject: store.SubjectSandbox}
	l.mu.Unlock()
	l.settle(handle, toolinstall.ExitEvent(code), code)
	return nil
}

// MarkSandboxUndone records that an in-process undo (a component removal, a
// config key restored, a placed file deleted) finished: the record moves to
// uninstalling and then to uninstalled (or uninstall_failed with undoErr),
// with display naming what was undone.
func (l *toolInstallLedger) MarkSandboxUndone(ctx context.Context, name string, id int64, display string, undoErr error) error {
	if l == nil {
		return errors.New("toolInstallLedger.MarkSandboxUndone: no install ledger in this process")
	}
	if _, err := l.latestSandbox(ctx, name, id); err != nil {
		return err
	}
	_, claimed, err := l.st.ClaimUninstallRecord(ctx, store.SubjectSandbox, id, uninstallFrom(), string(toolinstall.StatusUninstalling), []string{"observer-undo", name}, display, l.now())
	if err != nil {
		return err
	}
	if !claimed {
		return dashapi.ErrToolInstallStale
	}
	code := 0
	if undoErr != nil {
		code = 1
	}
	to, _ := toolinstall.Next(toolinstall.StatusUninstalling, toolinstall.ExitEvent(code))
	_, err = l.st.FinishUninstallRecord(ctx, store.SubjectSandbox, id, string(toolinstall.StatusUninstalling), store.ToolInstallFinish{Status: string(to), ExitCode: code, At: l.now()})
	if err == nil {
		l.sandboxSettled(id)
	}
	return err
}
