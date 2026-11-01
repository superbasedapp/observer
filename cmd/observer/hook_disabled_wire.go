package main

import (
	"context"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/hookdisable"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// hooksDisabledVerdict is the guard event for a vendor switch that turned
// every hook off (hook-parity T-046): a guard_error flag (nothing was
// blocked; Observer simply stops seeing those tools), degraded_from
// "hooks_disabled", so it reaches the org on the normal guard_events push
// exactly as a posture tamper does (postureTamperVerdict). A project-scope
// switch (T-910) carries its project root, so the event sits with that
// project.
func hooksDisabledVerdict(f hookdisable.Finding, at time.Time) guard.ActionVerdict {
	where := ""
	if f.ProjectRoot != "" {
		where = " in project " + f.ProjectRoot
	}
	return guard.ActionVerdict{
		Input:    guard.ActionInput{Tool: "observer", Target: f.Path, ProjectRoot: f.ProjectRoot, Timestamp: at.UTC()},
		Kind:     policy.KindConfigChange,
		Category: "guard",
		Verdict: policy.Verdict{
			Decision: policy.DecisionFlag,
			RuleID:   guard.GuardErrorRuleID,
			Severity: policy.SeverityHigh,
			Reason:   guardEventReason("hooks switched off: " + f.Key + " in " + f.Path + " (" + string(f.Scope) + " scope); " + f.Effect),
			Advice:   "Observer's hooks no longer run on " + strings.Join(f.Tools, ", ") + where + ". Remove the setting, or run `observer doctor hooks` for detail.",
			Source:   policy.SourceBuiltin,
		},
		GuardError:   true,
		DegradedFrom: "hooks_disabled",
	}
}

// hookProjectScanInterval spaces the project-scope scan (up to
// hookdisable.MaxProjectRoots projects, a few small file reads each) wider
// than the hook loop's own tick.
const hookProjectScanInterval = 30 * time.Second

// hookDisableWatch is the daemon's ONE watcher of vendor hook-disable
// switches. A switch is reported when it turns on (and once at daemon start
// when it is already on), never on every tick. User and managed switches
// are read every tick; project switches (T-910) every projectEvery, for the
// most recently active projects the store knows, and the last project
// result stands in between so the tracker does not see them clear.
type hookDisableWatch struct {
	home string
	goos string
	read func(string) ([]byte, error)
	// getenv reads the env-scope rows and the relocation variables of the
	// user rows under the pinned-home rule (crossmount.HomeEnvAt, FU-129):
	// the daemon's environment, the one the tools it launches start in,
	// unless its home is isolated, when it reads none, as the
	// managed-integrity layers do. nil skips the env-scope rows.
	getenv func(string) string
	// roots lists the project roots to scan, most recent first. Nil skips
	// project scope; an error keeps the previous project result.
	roots        func(ctx context.Context) ([]string, error)
	projectEvery time.Duration
	lastProject  time.Time
	project      []hookdisable.Finding
	tracker      hookdisable.Tracker
}

// projectRootLister is the store seam the watch reads project roots from.
type projectRootLister interface {
	RecentProjectRoots(ctx context.Context, limit int) ([]string, error)
}

func newHookDisableWatch(st projectRootLister) *hookDisableWatch {
	home, _ := os.UserHomeDir()
	w := &hookDisableWatch{home: home, goos: runtime.GOOS, read: diag.ReadHookSwitchFile, getenv: crossmount.HomeEnvAt(home, nil), projectEvery: hookProjectScanInterval}
	if st != nil {
		w.roots = func(ctx context.Context) ([]string, error) {
			return st.RecentProjectRoots(ctx, hookdisable.MaxProjectRoots)
		}
	}
	return w
}

// verdictPersister is the store seam the watch writes through.
type verdictPersister interface {
	PersistGuardVerdicts(ctx context.Context, vs []guard.ActionVerdict) (int, error)
}

// detect is one tick's full finding set: user and managed scope read now,
// project scope read when due.
func (w *hookDisableWatch) detect(ctx context.Context, now time.Time) []hookdisable.Finding {
	fs := hookdisable.Detect(diag.HookSwitchInputs(hookdisable.Options{Home: w.home, GOOS: w.goos, Getenv: w.getenv, ReadFile: w.read}))
	if w.roots != nil && (w.lastProject.IsZero() || now.Sub(w.lastProject) >= w.projectEvery) {
		if roots, err := w.roots(ctx); err == nil {
			w.project = hookdisable.Detect(hookdisable.Options{ProjectRoots: roots, ReadFile: w.read})
			w.lastProject = now
		}
	}
	return append(fs, w.project...)
}

// check detects, and persists a guard event per switch that turned on.
// Returns the number of events persisted.
func (w *hookDisableWatch) check(ctx context.Context, st verdictPersister, now time.Time, logger *slog.Logger) int {
	turned := w.tracker.Turned(w.detect(ctx, now))
	if len(turned) == 0 || st == nil {
		return 0
	}
	vs := make([]guard.ActionVerdict, 0, len(turned))
	for _, f := range turned {
		logger.Warn("vendor switch turned hooks off", "file", f.Path, "key", f.Key, "scope", f.Scope, "tools", f.Tools)
		vs = append(vs, hooksDisabledVerdict(f, now))
	}
	if _, err := st.PersistGuardVerdicts(ctx, vs); err != nil {
		logger.Warn("hooks disabled: persist guard events", "err", err)
		return 0
	}
	return len(vs)
}
