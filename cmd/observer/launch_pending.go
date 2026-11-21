//go:build !sbo_omit_terminals

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/marmutapp/superbased-observer/internal/agentlaunch"
	"github.com/marmutapp/superbased-observer/internal/attachsock"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// launch_pending.go is the daemon's ONE owner of launches held for a human
// (lane cli-2 fixes-1, the plans orchestrator's ruling on audit M2; the
// operator's decision is "ask on each launch"). A launch the daemon
// attributes to an agent (launch_initiator.go) is not started: the attach
// endpoint (`observer launch`, `observer <tool> --attach`) and the dashboard's
// launch routes (internal/intelligence/dashboard launch_hold.go) hold it here
// with an action that starts exactly that request. A human confirms it once,
// before it expires (agentlaunch.DefaultPendingTTL), with `observer terminals
// confirm <id>` or on the Terminals page; a caller attributed to an agent (or
// inside a box) may not confirm (agentlaunch.MayConfirm). The decision tables
// and the store are internal/agentlaunch's; this file adds the actions, the
// ids and the two front ends' shapes.

// pendingOutcome is what starting a held launch produced: the run (an
// attach-endpoint launch) or the replayed dashboard answer.
type pendingOutcome struct {
	run  *attachsock.RunInfo
	http dashapi.PendingLaunchResult
}

// pendingAction starts one held launch. ctx carries the held origin
// (withHeldOrigin), so the launch records the agent, not the confirmer.
type pendingAction func(ctx context.Context) (pendingOutcome, error)

// pendingLaunchStore is the store, shared by the attach endpoint and the
// dashboard (dashapi.PendingLaunches).
type pendingLaunchStore struct {
	holds *agentlaunch.Holds[pendingAction]
}

// newPendingLaunchStore builds the store over the wall clock and random ids.
func newPendingLaunchStore() *pendingLaunchStore {
	return &pendingLaunchStore{holds: agentlaunch.NewHolds[pendingAction](time.Now, newPendingID)}
}

// newPendingID is a short random id ("pend-" + 12 hex digits).
func newPendingID() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "pend-" + hex.EncodeToString(b[:]), nil
}

// heldOriginKey carries the origin of a confirmed hold into its action.
type heldOriginKey struct{}

// withHeldOrigin marks ctx as running a confirmed hold of origin o.
func withHeldOrigin(ctx context.Context, o termrun.Origin) context.Context {
	return context.WithValue(ctx, heldOriginKey{}, o)
}

// heldOrigin returns the origin of a confirmed hold, false otherwise.
func heldOrigin(ctx context.Context) (termrun.Origin, bool) {
	o, ok := ctx.Value(heldOriginKey{}).(termrun.Origin)
	return o, ok
}

// hold records a launch with its action.
func (p *pendingLaunchStore) hold(pend agentlaunch.Pending, a pendingAction) (agentlaunch.Pending, error) {
	return p.holds.Hold(pend, a)
}

// confirm checks the confirming caller (refused before the hold is taken,
// so a refused confirm does not consume it), takes the hold once and runs
// its action with the held origin.
func (p *pendingLaunchStore) confirm(ctx context.Context, id string, confirmer agentlaunch.ConfirmFacts) (agentlaunch.Pending, pendingOutcome, error) {
	if ok, why, _ := agentlaunch.MayConfirm(confirmer); !ok {
		return agentlaunch.Pending{}, pendingOutcome{}, &agentlaunch.Error{Code: agentlaunch.CodeConfirmRefused, Field: "confirm", Message: why}
	}
	held, action, err := p.holds.Take(id)
	if err != nil {
		return agentlaunch.Pending{}, pendingOutcome{}, &agentlaunch.Error{Code: agentlaunch.CodePendingNotFound, Field: "id", Message: err.Error()}
	}
	// The launch outlives the confirm request.
	runCtx := withHeldOrigin(context.WithoutCancel(ctx), held.Origin)
	out, err := action(runCtx)
	return held, out, err
}

// reject drops a hold without starting it.
func (p *pendingLaunchStore) reject(id string) (agentlaunch.Pending, error) {
	held, _, err := p.holds.Take(id)
	if err != nil {
		return agentlaunch.Pending{}, &agentlaunch.Error{Code: agentlaunch.CodePendingNotFound, Field: "id", Message: err.Error()}
	}
	return held, nil
}

// --- dashapi.PendingLaunches (the dashboard's half) ---

// dashboardPending adapts the store to the dashboard's plain types.
type dashboardPending struct{ p *pendingLaunchStore }

var _ dashapi.PendingLaunches = dashboardPending{}

func toDashPending(h agentlaunch.Pending) dashapi.PendingLaunch {
	var details []dashapi.PendingLaunchDetail
	for _, d := range h.Details {
		details = append(details, dashapi.PendingLaunchDetail{Label: d.Label, Value: d.Value, Warn: d.Warn})
	}
	return dashapi.PendingLaunch{
		Details: details,
		ID:      h.ID, Front: string(h.Front), What: h.What, Tool: h.Tool, Project: h.Project, Sandbox: h.Sandbox,
		Initiator: string(h.Origin.Initiator), ParentSessionID: h.Origin.ParentSessionID,
		CreatedAt: h.CreatedAt, ExpiresAt: h.ExpiresAt,
	}
}

// toDashError maps an agentlaunch refusal onto the dashboard's coded error.
func toDashError(err error) error {
	if code := agentlaunch.CodeOf(err); code != "" {
		return &dashapi.PendingLaunchError{Code: code, Message: err.Error()}
	}
	return err
}

// Hold implements dashapi.PendingLaunches.
func (d dashboardPending) Hold(p dashapi.PendingLaunch, start func(ctx context.Context) (dashapi.PendingLaunchResult, error)) (dashapi.PendingLaunch, error) {
	var details []agentlaunch.PendingDetail
	for _, d := range p.Details {
		details = append(details, agentlaunch.PendingDetail{Label: d.Label, Value: d.Value, Warn: d.Warn})
	}
	held, err := d.p.hold(agentlaunch.Pending{
		Front: agentlaunch.FrontDashboard, What: p.What, Tool: p.Tool, Project: p.Project, Sandbox: p.Sandbox, Details: details,
		Origin: termrun.Origin{Initiator: termrun.Initiator(p.Initiator), ParentSessionID: p.ParentSessionID},
	}, func(ctx context.Context) (pendingOutcome, error) {
		res, err := start(ctx)
		return pendingOutcome{http: res}, err
	})
	if err != nil {
		return dashapi.PendingLaunch{}, toDashError(err)
	}
	return toDashPending(held), nil
}

// List implements dashapi.PendingLaunches.
func (d dashboardPending) List() []dashapi.PendingLaunch {
	list := d.p.holds.List()
	out := make([]dashapi.PendingLaunch, 0, len(list))
	for _, h := range list {
		out = append(out, toDashPending(h))
	}
	return out
}

// Confirm implements dashapi.PendingLaunches. The dashboard's caller check
// has already refused a caller inside a box.
func (d dashboardPending) Confirm(ctx context.Context, id, confirmerInitiator string) (dashapi.PendingLaunch, dashapi.PendingLaunchResult, error) {
	held, out, err := d.p.confirm(ctx, id, agentlaunch.ConfirmFacts{Origin: termrun.Origin{Initiator: termrun.Initiator(confirmerInitiator)}})
	if err != nil {
		return dashapi.PendingLaunch{}, dashapi.PendingLaunchResult{}, toDashError(err)
	}
	return toDashPending(held), outcomeHTTP(out), nil
}

// Reject implements dashapi.PendingLaunches.
func (d dashboardPending) Reject(id string) (dashapi.PendingLaunch, error) {
	held, err := d.p.reject(id)
	if err != nil {
		return dashapi.PendingLaunch{}, toDashError(err)
	}
	return toDashPending(held), nil
}

// outcomeHTTP is a started hold's answer for an HTTP caller: the replayed
// dashboard answer, or the run of an attach-endpoint launch as JSON.
func outcomeHTTP(out pendingOutcome) dashapi.PendingLaunchResult {
	if out.run == nil {
		return out.http
	}
	body, _ := json.Marshal(map[string]any{"run": out.run})
	return dashapi.PendingLaunchResult{Status: http.StatusOK, ContentType: "application/json", Body: body}
}

// outcomeRun is a started hold's answer for the attach endpoint: the run,
// or what the replayed dashboard answer names (its run id and handle when
// it carries them).
func outcomeRun(held agentlaunch.Pending, out pendingOutcome) attachsock.RunInfo {
	if out.run != nil {
		return *out.run
	}
	var b struct {
		Handle string `json:"handle"`
		RunID  string `json:"run_id"`
		Error  string `json:"error"`
	}
	_ = json.Unmarshal(out.http.Body, &b)
	ri := attachsock.RunInfo{
		RunID: b.RunID, Handle: b.Handle, Tool: held.Tool, State: attachsock.StateRunning,
		Initiator: string(held.Origin.Initiator), ParentSessionID: held.Origin.ParentSessionID,
	}
	if out.http.Status >= 300 {
		ri.State, ri.EndReason = attachsock.StateEnded, "the confirmed launch was refused: "+b.Error
	}
	return ri
}

// pendingRunInfo is a hold as the attach endpoint reports it.
func pendingRunInfo(h agentlaunch.Pending) attachsock.RunInfo {
	return attachsock.RunInfo{
		Sandboxed: h.Sandbox != "" && h.Sandbox != agentlaunch.SandboxNone, Backend: h.Sandbox,
		Tool: h.Tool, State: attachsock.StatePending, PendingID: h.ID, PendingWhat: h.What, PendingDetails: toRunDetails(h.Details),
		ExpiresAt: stamp(h.ExpiresAt), LaunchedAt: stamp(h.CreatedAt),
		Initiator: string(h.Origin.Initiator), ParentSessionID: h.Origin.ParentSessionID,
	}
}

// errNoPendingStore: the hold cannot be made, so the agent's launch is
// refused rather than run unconfirmed.
var errNoPendingStore = errors.New("an agent asked for this launch and it needs a human's confirm, but this daemon cannot hold it; start the run yourself")
