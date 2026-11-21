//go:build !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/agentlaunch"
	"github.com/marmutapp/superbased-observer/internal/attachsock"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/runstate"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termcore"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// launch_control.go is the daemon side of `observer launch` and `observer
// terminals` (decision P-228, phase 1b): the attachsock.Controller the attach
// host offers. It owns no launch logic of its own. A detached launch walks
// internal/agentlaunch's validation rows and backend choice table against
// the daemon's own sandbox probe, then runs the dashboard's own fresh-launch
// path (launchManagerAdapter.createFresh: the launch-gate table, then
// termsvc.LaunchFresh), so the New Terminal dialog and the CLI can never
// differ in what they allow. The run inventory reads the PTY manager's live
// snapshot and the node-local terminal_run history.

// launchHistoryLimit bounds the history rows `observer terminals ls` reads.
const launchHistoryLimit = 50

// launchControl implements attachsock.Controller. Every dependency is a
// function so the tests drive it with fakes (no store, no PTY).
type launchControl struct {
	// fresh is launchManagerAdapter.createFresh.
	fresh func(spec dashapi.FreshLaunchSpec) (termsvc.LaunchResult, bool, error)
	// probe is the daemon's sandbox prober; nil means no sandbox support.
	probe func(ctx context.Context) dashapi.SandboxAvailability
	// snapshot lists the PTY manager's sessions (launchManagerAdapter.Snapshot).
	snapshot func() []dashapi.LaunchInfo
	// sessionFor resolves a run's correlated session (termsvc.SessionForRun).
	sessionFor func(runID string) (string, bool)
	// endReason is the end reason marked or recorded for a live handle.
	endReason func(handle string) string
	// stop ends a live handle: it marks the reason, then closes the PTY.
	stop func(handle, reason string)
	// history reads terminal_run (nil when no DB is wired).
	history func(ctx context.Context, limit int) ([]store.TerminalRunSummary, error)
	// modelOffered judges a requested model against the list the dashboard's
	// picker offers (dashapi.ModelOffered); nil skips the check.
	modelOffered func(ctx context.Context, tool, model string) bool
	// refreshRoots kicks the watcher's root refresh after a launch (nil-safe).
	refreshRoots func()
	// origin resolves who started a detached launch (lane cli-2,
	// launch_initiator.go): the attach endpoint's caller and the client's
	// agent-session hint, or a coded refusal when that caller is gone
	// (fixes-3, audit M1). nil records nothing.
	origin func(ctx context.Context, spec attachsock.LaunchSpec) (termrun.Origin, error)
	// pending is the store an agent's launch is held in for a human (lane
	// cli-2 fixes-1, launch_pending.go); nil refuses an agent's launch.
	pending *pendingLaunchStore
	// confirmer resolves the caller of a confirm (the attach endpoint's
	// peer) into the facts agentlaunch.MayConfirm judges.
	confirmer func(ctx context.Context) agentlaunch.ConfirmFacts
	now       func() time.Time
}

// newLaunchControl builds the controller over the shared terminal stack.
func newLaunchControl(s *terminalStack) *launchControl {
	a := s.launchManager()
	c := &launchControl{
		fresh:      a.createFresh,
		snapshot:   a.Snapshot,
		sessionFor: s.svc.SessionForRun,
		endReason:  s.svc.EndReasonForHandle,
		stop: func(handle, reason string) {
			s.svc.MarkEnding(handle, reason)
			s.mgr.Close(handle)
		},
		history:      s.runHistory,
		modelOffered: s.modelOffered,
		now:          time.Now,
	}
	li := s.launchInitiator()
	c.origin = attachLaunchOrigin(li)
	c.pending = s.pending
	c.confirmer = launchConfirmer(li)
	if s.sandboxProber != nil {
		c.probe = s.sandboxProber.ProbeSandbox
	}
	return c
}

// controlRefusal builds the coded refusal the attach channel relays.
func controlRefusal(code string, err error) error {
	return &attachsock.ControlError{Code: code, Message: err.Error()}
}

// LaunchDetached implements attachsock.Controller.
func (c *launchControl) LaunchDetached(ctx context.Context, spec attachsock.LaunchSpec) (attachsock.RunInfo, error) {
	n, err := agentlaunch.Normalize(agentlaunch.Request{
		Tool: spec.Tool, Project: spec.Project, Sandbox: spec.Sandbox,
		Workspace: spec.Workspace, Remote: spec.Remote, Branch: spec.Branch, Model: spec.Model,
	})
	if err != nil {
		return attachsock.RunInfo{}, controlRefusal(agentlaunch.CodeOf(err), err)
	}
	// The dashboard silently drops a model its picker does not offer; a
	// script that asked for one is told instead (audit L3).
	if n.Model != "" && c.modelOffered != nil && !c.modelOffered(ctx, n.Tool, n.Model) {
		return attachsock.RunInfo{}, controlRefusal(agentlaunch.CodeInvalid, fmt.Errorf(
			"--model %q is not a model the dashboard offers for %s (its recent models and the registry's known ones; see the New Terminal model picker)", n.Model, n.Tool))
	}
	choice := agentlaunch.Choice{}
	if n.Sandboxed {
		if c.probe == nil {
			return attachsock.RunInfo{}, controlRefusal(agentlaunch.CodeSandboxUnavailable,
				errors.New("this daemon has no sandbox support ([terminal.sandbox] is not wired); nothing was launched"))
		}
		choice, err = agentlaunch.Choose(n, probeRows(c.probe(ctx)))
		if err != nil {
			return attachsock.RunInfo{}, controlRefusal(agentlaunch.CodeOf(err), err)
		}
	}
	origin, confirmed := heldOrigin(ctx)
	if !confirmed && c.origin != nil {
		// A caller that is gone is refused, neither held nor run as a
		// human's (fixes-3, audit M1).
		if origin, err = c.origin(ctx, spec); err != nil {
			return attachsock.RunInfo{}, controlRefusal(agentlaunch.CodeOf(err), err)
		}
	}
	// An agent's launch is held for a human (lane cli-2 fixes-1): it starts
	// only when `observer terminals confirm` (or the Terminals page) names
	// this hold, and then walks every row above again.
	if hold, _ := agentlaunch.ShouldHold(origin); hold && !confirmed {
		return c.holdLaunch(spec, n, origin)
	}
	res, gateRefused, err := c.fresh(dashapi.FreshLaunchSpec{
		Initiator:       string(origin.Initiator),
		ParentSessionID: origin.ParentSessionID,
		Tool:            n.Tool,
		Subcommand:      n.Subcommand,
		ProjectRoot:     n.Project,
		Model:           n.Model,
		Sandbox:         choice.Sandboxed,
		WorkspaceSource: n.Workspace,
		WorkspaceRemote: n.Remote,
		WorkspaceBranch: n.Branch,
		Backend:         choice.Backend,
		// A detached launch cannot answer the inline sign-in question:
		// it starts with the remembered consent, else without the copy.
	})
	if err != nil {
		return attachsock.RunInfo{}, controlRefusal(freshErrorCode(err, gateRefused), err)
	}
	if c.refreshRoots != nil {
		c.refreshRoots()
	}
	if ri, ferr := c.find(ctx, res.RunID); ferr == nil {
		return ri, nil
	}
	return attachsock.RunInfo{
		RunID: res.RunID, Handle: res.Handle, Tool: n.Tool, Subcommand: n.Subcommand,
		Kind: string(termrun.KindFresh), State: attachsock.StateRunning, Sandboxed: choice.Sandboxed,
		Initiator: string(origin.Initiator), ParentSessionID: origin.ParentSessionID,
	}, nil
}

// launchConfirmer is the confirm check of the attach endpoint (lane cli-2
// fixes-2, audit H-A): the confirming caller is judged exactly like a
// launching one, by its ancestry, by the marker the daemon reads from its
// own and its ancestors' environment (launchInitiator.envMarker), and by the
// hint the client reported (CallerHintOf), so an agent that runs `observer
// terminals confirm` on its own held launch is refused. A caller that is
// no longer the process that connected is refused too (fixes-3, audit M1:
// agentlaunch row K0-caller-gone).
func launchConfirmer(li launchInitiator) func(ctx context.Context) agentlaunch.ConfirmFacts {
	return func(ctx context.Context) agentlaunch.ConfirmFacts {
		h := attachsock.CallerHintOf(ctx)
		o, gone := li.attachCaller(ctx, h.AgentEnv, h.Session)
		return agentlaunch.ConfirmFacts{Origin: o, CallerGone: gone != "", GoneWhy: gone}
	}
}

// attachLaunchOrigin is the origin check of an `observer launch` on the
// attach endpoint: the caller judged like a confirming one, with the hint
// its spec carries, and a coded refusal (agentlaunch.CodeCallerGone) when
// the caller is gone (fixes-3, audit M1).
func attachLaunchOrigin(li launchInitiator) func(ctx context.Context, spec attachsock.LaunchSpec) (termrun.Origin, error) {
	return func(ctx context.Context, spec attachsock.LaunchSpec) (termrun.Origin, error) {
		o, gone := li.attachCaller(ctx, spec.AgentEnv, spec.AgentEnvSession)
		if gone != "" {
			return termrun.Origin{}, agentlaunch.CallerGoneError(gone)
		}
		return o, nil
	}
}

// holdLaunch holds an agent's detached launch for a human and reports the
// hold (StatePending). Its action is this launch control's own
// LaunchDetached over the same spec, under the held origin.
func (c *launchControl) holdLaunch(spec attachsock.LaunchSpec, n agentlaunch.Normalized, origin termrun.Origin) (attachsock.RunInfo, error) {
	if c.pending == nil {
		return attachsock.RunInfo{}, controlRefusal(agentlaunch.CodeRefused, errNoPendingStore)
	}
	what := "observer launch " + n.Subcommand + " in " + n.Project
	sandbox := ""
	if n.Sandboxed {
		sandbox = n.Backend
		if n.Auto {
			sandbox = agentlaunch.SandboxAuto
		}
		what += ", sandbox " + sandbox + ", workspace " + n.Workspace
	}
	held, err := c.pending.hold(agentlaunch.Pending{
		Front: agentlaunch.FrontCLI, What: what, Tool: n.Tool, Project: n.Project, Sandbox: sandbox, Origin: origin,
		Details: launchSpecDetails(spec),
	}, func(ctx context.Context) (pendingOutcome, error) {
		ri, err := c.LaunchDetached(ctx, spec)
		if err != nil {
			return pendingOutcome{}, err
		}
		return pendingOutcome{run: &ri}, nil
	})
	if err != nil {
		return attachsock.RunInfo{}, controlRefusal(agentlaunch.CodeOf(err), err)
	}
	return pendingRunInfo(held), nil
}

// ConfirmLaunch implements attachsock.PendingController: the caller of the
// confirm (the endpoint's peer) must not be an agent's.
func (c *launchControl) ConfirmLaunch(ctx context.Context, id string) (attachsock.RunInfo, error) {
	if c.pending == nil {
		return attachsock.RunInfo{}, controlRefusal(attachsock.CodeUnsupported, errors.New("this daemon holds no launches"))
	}
	var facts agentlaunch.ConfirmFacts
	if c.confirmer != nil {
		facts = c.confirmer(ctx)
	}
	held, out, err := c.pending.confirm(ctx, strings.TrimSpace(id), facts)
	if err != nil {
		code := agentlaunch.CodeOf(err)
		if code == "" {
			code = agentlaunch.CodeFailed
		}
		return attachsock.RunInfo{}, controlRefusal(code, err)
	}
	return outcomeRun(held, out), nil
}

// RejectLaunch implements attachsock.PendingController.
func (c *launchControl) RejectLaunch(_ context.Context, id string) (attachsock.RunInfo, error) {
	if c.pending == nil {
		return attachsock.RunInfo{}, controlRefusal(attachsock.CodeUnsupported, errors.New("this daemon holds no launches"))
	}
	held, err := c.pending.reject(strings.TrimSpace(id))
	if err != nil {
		return attachsock.RunInfo{}, controlRefusal(agentlaunch.CodeOf(err), err)
	}
	ri := pendingRunInfo(held)
	ri.State = attachsock.StateEnded
	ri.EndReason = "rejected"
	return ri, nil
}

// freshCodes maps the fresh-launch sentinels onto the closed refusal codes,
// walked top-down; the first match wins.
var freshCodes = []struct {
	err  error
	code string
}{
	{dashapi.ErrLaunchTooMany, agentlaunch.CodeTooMany},
	{termcore.ErrSandboxUnavailable, agentlaunch.CodeSandboxUnavailable},
	{termcore.ErrWorkspacePrepFailed, agentlaunch.CodeSandboxUnavailable},
	{dashapi.ErrLaunchFreshDisabled, agentlaunch.CodeRefused},
	{dashapi.ErrLaunchToolNotAllowed, agentlaunch.CodeRefused},
	{dashapi.ErrLaunchProjectRootDenied, agentlaunch.CodeRefused},
	{dashapi.ErrLaunchSandboxRequired, agentlaunch.CodeRefused},
	{termsvc.ErrTerminalNotAllowed, agentlaunch.CodeRefused},
	{dashapi.ErrLaunchUnsupported, agentlaunch.CodeFailed},
}

// freshErrorCode is the refusal code for a failed fresh launch: a sentinel
// row, else a launch-gate refusal, else a plain failure.
func freshErrorCode(err error, gateRefused bool) string {
	for _, row := range freshCodes {
		if errors.Is(err, row.err) {
			return row.code
		}
	}
	if gateRefused {
		return agentlaunch.CodeRefused
	}
	return agentlaunch.CodeFailed
}

// probeRows maps the dashboard's sandbox probe onto agentlaunch's plain rows.
func probeRows(av dashapi.SandboxAvailability) agentlaunch.Probe {
	p := agentlaunch.Probe{Available: av.Available, Verdict: av.Verdict, Reason: av.Reason, Tools: map[string]agentlaunch.ToolRow{}}
	for _, b := range av.Backends {
		p.Backends = append(p.Backends, agentlaunch.BackendRow{
			ID: b.ID, Maturity: b.Maturity, Available: b.Available,
			Verification: b.Verification, Verdict: b.Verdict, Reason: b.Reason,
		})
	}
	for _, s := range av.Sources {
		p.Sources = append(p.Sources, agentlaunch.SourceRow{ID: s.ID, Available: s.Available, Reason: s.Reason})
	}
	for tool, t := range av.Tools {
		p.Tools[tool] = agentlaunch.ToolRow{Available: t.Available, Reason: t.Reason}
	}
	return p
}

// Runs implements attachsock.Controller: daemon-owned terminals first
// (newest first), then the recorded history this daemon holds no PTY for.
func (c *launchControl) Runs(ctx context.Context) ([]attachsock.RunInfo, error) {
	live := c.liveRuns()
	// Launches held for a human come first (lane cli-2 fixes-1).
	var out []attachsock.RunInfo
	if c.pending != nil {
		for _, h := range c.pending.holds.List() {
			out = append(out, pendingRunInfo(h))
		}
	}
	out = append(out, live...)
	seen := make(map[string]bool, len(live))
	for _, r := range live {
		seen[r.RunID] = true
	}
	if c.history != nil {
		hist, err := c.history(ctx, launchHistoryLimit)
		if err != nil {
			return nil, fmt.Errorf("launch control: run history: %w", err)
		}
		for _, h := range hist {
			if seen[h.RunID] {
				continue
			}
			out = append(out, c.historyRun(h))
		}
	}
	return out, nil
}

// liveRuns maps the PTY manager's snapshot, newest first. Setup sessions
// (guided installs) and kindless sessions are not agent runs.
func (c *launchControl) liveRuns() []attachsock.RunInfo {
	snap := c.snapshot()
	sort.SliceStable(snap, func(i, j int) bool { return snap[i].CreatedAt.After(snap[j].CreatedAt) })
	out := make([]attachsock.RunInfo, 0, len(snap))
	for _, s := range snap {
		if s.Setup || s.Kind == "" || s.RunID == "" {
			continue
		}
		ri := attachsock.RunInfo{
			RunID: s.RunID, Handle: s.ID, Tool: s.Tool, Subcommand: s.Subcommand, Kind: s.Kind,
			State: attachsock.StateRunning, Sandboxed: s.Sandboxed, LaunchedAt: stamp(s.CreatedAt),
			Initiator: s.Initiator, ParentSessionID: s.ParentSessionID,
		}
		if s.Exited {
			code := s.ExitCode
			ri.State, ri.ExitCode = attachsock.StateExited, &code
			ri.EndReason = c.endReasonOf(s.ID, code)
		}
		if s.Isolation != nil {
			ri.Isolation, ri.Backend, ri.Capture = s.Isolation.Class, s.Isolation.Backend, s.Isolation.CaptureLevel
		}
		if id, ok := c.sessionFor(s.RunID); ok {
			ri.SessionID = id
		}
		out = append(out, ri)
	}
	return out
}

func (c *launchControl) endReasonOf(handle string, code int) string {
	if c.endReason != nil {
		if r := c.endReason(handle); r != "" {
			return r
		}
	}
	return termrun.EndReasonForExit(code)
}

// historyRun maps one terminal_run row. A row with no end that is far too
// old to be live reads as abandoned, the dashboard's own read-time verdict
// (runstate is the one decision authority, /api/terminal/runs).
func (c *launchControl) historyRun(h store.TerminalRunSummary) attachsock.RunInfo {
	ri := attachsock.RunInfo{
		RunID: h.RunID, Tool: h.Tool, Kind: h.Kind, SessionID: h.BestSessionID,
		ExitCode: h.ExitCode, EndReason: h.EndReason, LaunchedAt: stamp(h.LaunchedAt),
		Initiator: h.Initiator, ParentSessionID: h.ParentSessionID,
	}
	// The recorded isolation evidence (migration 179): a run is sandboxed
	// when its launch recorded a class other than none; the backend is the
	// outermost layer of its stack.
	if h.IsolationClass != "" && h.IsolationClass != "none" {
		ri.Sandboxed, ri.Isolation, ri.Capture = true, h.IsolationClass, h.CaptureLevel
		ri.Backend, _, _ = strings.Cut(h.Stack, ",")
	}
	switch {
	case h.EndedAt != nil:
		ri.State, ri.EndedAt = attachsock.StateEnded, stamp(*h.EndedAt)
	default:
		ri.State = attachsock.StateRunning
		v := runstate.Reconcile(runstate.DefaultRules(), runstate.Signal{
			Kind: runstate.KindTerminalRun, Status: "running", Age: c.now().Sub(h.LaunchedAt),
		})
		if v.Changed {
			ri.State = attachsock.StateAbandoned
		}
	}
	return ri
}

// Run implements attachsock.Controller: an exact run id or handle, or a
// unique run-id prefix of at least 6 characters.
func (c *launchControl) Run(ctx context.Context, ref string) (attachsock.RunInfo, error) {
	return c.find(ctx, strings.TrimSpace(ref))
}

// minRunPrefix is the shortest run-id prefix a reference may use.
const minRunPrefix = 6

// maxAmbiguousNamed bounds the run ids an ambiguity refusal lists.
const maxAmbiguousNamed = 5

// find resolves ref: ErrRunNotFound when nothing matches, a CodeAmbiguousRun
// refusal naming the matches when a prefix matches more than one run.
func (c *launchControl) find(ctx context.Context, ref string) (attachsock.RunInfo, error) {
	notFound := fmt.Errorf("%w: %q", attachsock.ErrRunNotFound, ref)
	if ref == "" {
		return attachsock.RunInfo{}, notFound
	}
	// Fast path, the one a wait takes on every poll: a live terminal named
	// by its exact run id or handle, with no history read.
	for _, r := range c.liveRuns() {
		if r.RunID == ref || (r.Handle != "" && r.Handle == ref) {
			return r, nil
		}
	}
	runs, err := c.Runs(ctx)
	if err != nil {
		// The live half still answers when the history read fails.
		runs = c.liveRuns()
	}
	var prefixed []attachsock.RunInfo
	for _, r := range runs {
		if r.RunID == ref || (r.Handle != "" && r.Handle == ref) {
			return r, nil
		}
		if len(ref) >= minRunPrefix && strings.HasPrefix(r.RunID, ref) {
			prefixed = append(prefixed, r)
		}
	}
	switch len(prefixed) {
	case 0:
		return attachsock.RunInfo{}, notFound
	case 1:
		return prefixed[0], nil
	}
	ids := make([]string, 0, maxAmbiguousNamed)
	for i, r := range prefixed {
		if i == maxAmbiguousNamed {
			ids = append(ids, "...")
			break
		}
		ids = append(ids, r.RunID)
	}
	return attachsock.RunInfo{}, &attachsock.ControlError{
		Code:    attachsock.CodeAmbiguousRun,
		Message: fmt.Sprintf("run prefix %q is ambiguous: it matches %d runs (%s); give more of the run id", ref, len(prefixed), strings.Join(ids, ", ")),
	}
}

// StopRun implements attachsock.Controller. Only a terminal this daemon owns
// can be stopped here; its end records cli_stop.
func (c *launchControl) StopRun(ctx context.Context, ref string) (attachsock.RunInfo, error) {
	ri, err := c.Run(ctx, ref)
	if err != nil {
		return attachsock.RunInfo{}, err
	}
	if ri.Handle == "" {
		return attachsock.RunInfo{}, &attachsock.ControlError{
			Code:    attachsock.CodeNotStoppable,
			Message: fmt.Sprintf("run %s is not a terminal this daemon owns (state %s); stop it where it runs", ri.RunID, ri.State),
		}
	}
	if ri.State != attachsock.StateRunning {
		return ri, nil // already exited: nothing to stop
	}
	c.stop(ri.Handle, termrun.EndCLIStop)
	ri.State, ri.EndReason = attachsock.StateEnded, termrun.EndCLIStop
	return ri, nil
}

// stamp formats a time as RFC 3339 UTC, "" for the zero time.
func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
