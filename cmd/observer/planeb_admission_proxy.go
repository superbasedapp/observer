//go:build !sbo_omit_capture_proxy

package main

import (
	"context"
	"log/slog"

	"github.com/marmutapp/superbased-observer/internal/promptadmit"
	"github.com/marmutapp/superbased-observer/internal/proxy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// planeBPromptAdmitter adapts the node lane (planeb_admission_node.go) to the
// proxy's PromptAdmitter seam, so the proxy never imports the engine, the org
// client or the store.
type planeBPromptAdmitter struct{ lane *planeBNodeLane }

// PromptAdmissionActive implements proxy.PromptAdmitter: a cheap check that a
// node-lane policy is installed, so the proxy skips per-request identity work
// on every node that has none (every individual node included).
func (a planeBPromptAdmitter) PromptAdmissionActive() bool { return a.lane.active() }

// AdmitPrompt implements proxy.PromptAdmitter.
func (a planeBPromptAdmitter) AdmitPrompt(ctx context.Context, in proxy.PromptAdmitInput) proxy.PromptAdmitResult {
	o := a.lane.admit(ctx, planeBPromptInput{Provider: in.Provider, Body: in.Body, SessionID: in.SessionID, Tool: in.Tool})
	if o.Action != promptadmit.ActionBlock {
		return proxy.PromptAdmitResult{}
	}
	return proxy.PromptAdmitResult{Block: true, Reason: o.Reason, Criterion: o.Criterion}
}

// bindPlaneBNodeLane binds the daemon's node lane onto the proxy options. It
// is always bound: with no installed node-lane policy, or on an individual
// node, every request is admitted after one nil check. relay is the C1 judge
// relay (nil when not enrolled); st is the guard_events writer.
func bindPlaneBNodeLane(opts *proxy.Options, relay orgJudgeRelayFunc, st *store.Store, logger *slog.Logger) {
	configurePlaneBNodeLane(relay, st, logger)
	opts.PromptAdmitter = planeBPromptAdmitter{lane: processPlaneBLane}
}
