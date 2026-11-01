package diag

import (
	"context"
	"database/sql"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hookdisable"
	"github.com/marmutapp/superbased-observer/internal/hookliveness"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// hookLivenessWindow bounds the activity and sessions checkHookLiveness
// judges.
const hookLivenessWindow = 14 * 24 * time.Hour

// hookLivenessSessionCap bounds the sessions read per tool.
const hookLivenessSessionCap = 500

// checkHookLiveness reports, per tool with registered hook bindings, whether
// the hooks Observer registers actually fired (surface-gap review OBS-7):
// recorded in hook_activity by the daemon's hook spool drainer, judged by
// internal/hookliveness against the registry's bindings and the sessions
// the store captured in the last 14 days. A tool whose captured sessions
// show no hook activity on a surface is a warning (a host that never runs
// hooks, a project switch, a --no-hooks flag); a limit of what can be proven
// (activity with no session id, ids that do not join) is said, never
// guessed. Vendor file switches come from the same internal/hookdisable
// table the hooks.disabled check reads.
//
// getenv is the doctor's one lookup (DoctorOptions.Getenv, under the
// pinned-home rule, FU-129), as for hooks.disabled.
//
// Named "hooks.liveness" so `observer doctor hooks` scopes to it.
func checkHookLiveness(ctx context.Context, database *sql.DB, homeDir, homeOverride string, roots []string, now time.Time, getenv func(string) string) Check {
	const name = "hooks.liveness"
	if database == nil {
		return Check{Name: name, Status: StatusFail, Message: "no database handle"}
	}
	goos := runtime.GOOS
	if homeOverride != "" {
		goos = ""
	}
	switches := map[string][]string{}
	for _, f := range hookdisable.Detect(HookSwitchInputs(hookdisable.Options{Home: homeDir, GOOS: goos, ProjectRoots: roots, Getenv: getenv, ReadFile: ReadHookSwitchFile})) {
		if f.ReplayOnly {
			continue
		}
		for _, t := range f.Tools {
			switches[t] = append(switches[t], f.Key)
		}
	}
	verdicts, err := hookLivenessVerdicts(ctx, store.New(database), switches, now)
	if err != nil {
		return Check{Name: name, Status: StatusFail, Message: err.Error()}
	}
	return renderHookLiveness(name, verdicts)
}

// hookLivenessVerdicts loads the inputs and classifies every tool with a
// registered hook binding or recorded activity.
func hookLivenessVerdicts(ctx context.Context, st *store.Store, switches map[string][]string, now time.Time) ([]hookliveness.Verdict, error) {
	since := now.Add(-hookLivenessWindow)
	rows, err := st.LoadHookActivity(ctx, since)
	if err != nil {
		return nil, err
	}
	epoch, err := st.HookActivityEpoch(ctx)
	if err != nil {
		return nil, err
	}
	sessions, err := st.HookLivenessSessions(ctx, since, hookLivenessSessionCap)
	if err != nil {
		return nil, err
	}
	activity := map[string][]hookliveness.Activity{}
	for _, r := range rows {
		activity[r.Tool] = append(activity[r.Tool], hookliveness.Activity{
			Tool: r.Tool, Event: r.Event, SessionID: r.SessionID, Count: r.Count,
			FirstAt: r.FirstAt, LastAt: r.LastAt, EnvClasses: r.EnvClasses,
		})
	}
	var ins []hookliveness.ToolInput
	seen := map[string]bool{}
	for _, c := range integration.Capabilities() {
		in := hookliveness.ToolInput{Tool: c.Tool, Activity: activity[c.Tool], DisabledSwitches: switches[c.Tool]}
		for _, b := range c.Hook.Bindings {
			in.Events = append(in.Events, hookliveness.EventSpec{Native: b.NativeEvent, Registered: b.Registered, SessionKey: b.SessionKey})
		}
		for _, s := range sessions[c.Tool] {
			in.Sessions = append(in.Sessions, hookliveness.Session{ID: s.ID, Surface: s.Surface, StartedAt: s.StartedAt})
		}
		seen[c.Tool] = true
		ins = append(ins, in)
	}
	for tool, a := range activity {
		if !seen[tool] {
			ins = append(ins, hookliveness.ToolInput{Tool: tool, Activity: a})
		}
	}
	return hookliveness.ClassifyAll(ins, hookliveness.Options{Epoch: epoch, Now: now}), nil
}

// hookLivenessReasons is the sentence each tool rule renders, keyed by rule.
var hookLivenessReasons = map[hookliveness.Rule]string{
	hookliveness.RuleDisabledSwitch:     "a vendor switch turns its hooks off",
	hookliveness.RuleNotYetObserved:     "no hook activity recorded on this node yet; liveness cannot be judged",
	hookliveness.RuleNeverSeen:          "sessions were captured but no hook ever fired",
	hookliveness.RuleNoSessionKey:       "hooks fire; the payload carries no session id, so per-session liveness is unprovable",
	hookliveness.RuleUnattributedOnly:   "hooks fire, but only without a session id; per-session liveness is unprovable",
	hookliveness.RuleSessionIDsUnjoined: "hooks fire, but their session ids match no captured session; per-session liveness is not judged",
	hookliveness.RuleSilentOnSurface:    "no hook fired in any captured session on a surface",
	hookliveness.RuleSilentSomeSessions: "some captured sessions recorded no hook activity",
	hookliveness.RuleOK:                 "hooks fire in every judged session",
}

func renderHookLiveness(name string, verdicts []hookliveness.Verdict) Check {
	var details []string
	warn, okTools := 0, 0
	for _, v := range verdicts {
		if v.Severity == hookliveness.SeverityNone {
			continue
		}
		switch v.Severity {
		case hookliveness.SeverityWarn:
			warn++
		case hookliveness.SeverityOK:
			okTools++
		}
		details = append(details, renderHookLivenessVerdict(v))
	}
	if len(details) == 0 {
		return Check{Name: name, Status: StatusOK, Message: "no tool with registered hooks captured a session in the last 14 days"}
	}
	details = append(details, "hook activity without a session id never proves a session's hooks ran; it is counted apart")
	if warn > 0 {
		return Check{
			Name:    name,
			Status:  StatusWarn,
			Message: fmt.Sprintf("%d tool(s) captured sessions whose hooks did not fire (%d proven live)", warn, okTools),
			Details: details,
		}
	}
	return Check{
		Name:    name,
		Status:  StatusOK,
		Message: fmt.Sprintf("%d tool(s) with hooks proven live; no silent surface", okTools),
		Details: details,
	}
}

func renderHookLivenessVerdict(v hookliveness.Verdict) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s (%s)", v.Tool, v.Rule, hookLivenessReasons[v.Rule])
	if v.JudgedSessions > 0 {
		fmt.Fprintf(&b, "; %d of %d judged session(s) silent", v.SilentSessions, v.JudgedSessions)
	}
	if len(v.SilentSurfaces) > 0 {
		fmt.Fprintf(&b, "; silent surface(s): %s", strings.Join(v.SilentSurfaces, ", "))
	}
	if v.ExampleSilent != "" && v.Severity == hookliveness.SeverityWarn {
		fmt.Fprintf(&b, ", e.g. session %s", v.ExampleSilent)
	}
	if len(v.DisabledSwitches) > 0 {
		fmt.Fprintf(&b, "; switch: %s", strings.Join(v.DisabledSwitches, ", "))
	}
	if v.Unattributed > 0 {
		fmt.Fprintf(&b, "; %d call(s) without a session id", v.Unattributed)
	}
	var seen, never []string
	for _, e := range v.Events {
		switch e.Rule {
		case hookliveness.EventSeen, hookliveness.EventSeenUnattributed:
			seen = append(seen, e.Event)
		case hookliveness.EventNeverSeen:
			never = append(never, e.Event)
		case hookliveness.EventSeenUnregistered:
			seen = append(seen, e.Event+" (not registered)")
		}
	}
	if len(seen) > 0 {
		fmt.Fprintf(&b, "; seen: %s", strings.Join(seen, ", "))
	}
	if len(never) > 0 && v.Rule != hookliveness.RuleNotYetObserved {
		fmt.Fprintf(&b, "; never seen: %s", strings.Join(never, ", "))
	}
	if route := renderHookLivenessEnv(v.EnvSessions); route != "" {
		fmt.Fprintf(&b, "; route seen by hooks: %s", route)
	}
	if len(v.OutOfFileSwitches) > 0 {
		fmt.Fprintf(&b, "; check for %s", strings.Join(v.OutOfFileSwitches, " or "))
	}
	return b.String()
}

// renderHookLivenessEnv renders the per-session env classes as
// "NAME class=n, ..." in name order.
func renderHookLivenessEnv(env map[string]map[string]int) string {
	if len(env) == 0 {
		return ""
	}
	names := make([]string, 0, len(env))
	for n := range env {
		names = append(names, n)
	}
	sort.Strings(names)
	var parts []string
	for _, n := range names {
		classes := make([]string, 0, len(env[n]))
		for c := range env[n] {
			classes = append(classes, c)
		}
		sort.Strings(classes)
		var cs []string
		for _, c := range classes {
			cs = append(cs, fmt.Sprintf("%s=%d", c, env[n][c]))
		}
		parts = append(parts, n+" "+strings.Join(cs, " "))
	}
	return strings.Join(parts, ", ")
}

// HookSilentTools returns, sorted, the tools whose captured sessions in the
// liveness window show their registered hooks never firing (rule
// hooks_never_seen) or never firing on some surface (rule
// hooks_silent_on_surface): the tools the managed-integrity report locates
// the hook_silent_surface capture risk on. File switches are left to the
// hooks.disabled path (they already reach the org as guard events), so a
// tool silenced by one is not double-reported here.
func HookSilentTools(ctx context.Context, st *store.Store, now time.Time) ([]string, error) {
	verdicts, err := hookLivenessVerdicts(ctx, st, nil, now)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, v := range verdicts {
		if hookSilentRules[v.Rule] {
			out = append(out, v.Tool)
		}
	}
	sort.Strings(out)
	return out, nil
}

// hookSilentRules are the tool rules that report hook_silent_surface.
var hookSilentRules = map[hookliveness.Rule]bool{
	hookliveness.RuleNeverSeen:       true,
	hookliveness.RuleSilentOnSurface: true,
}
