package main

import (
	"context"
	"sync/atomic"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/routingcore"
)

// routing_core.go is the always-linked half of the routing wiring (lane
// MP-L1I, T-715): the router's state handle (read by the effective-policy
// reporter and start.go, nil-safe so a build without a router passes nil)
// and the cost-engine price adapter advise and the model value report use.
// Everything that links internal/routing or internal/routingconfig is
// tagged !sbo_omit_proxy_routing; routing_omit.go stands in for it.

// routingPriceFn adapts the cost engine to the routing vocabulary's
// injected pricing seam. internal/mcp keeps an identical adapter
// (mcpRoutingPriceFn); a change here must be made there too.
func routingPriceFn(engine *cost.Engine) routingcore.PriceFn {
	return func(model string, u routingcore.PromptUsage) (float64, bool) {
		return engine.Compute(model, cost.TokenBundle{
			Input:             u.Input,
			Output:            u.Output,
			CacheRead:         u.CacheRead,
			CacheCreation:     u.CacheCreation,
			CacheCreation1h:   u.CacheCreation1h,
			Reasoning:         u.Reasoning,
			WebSearchRequests: u.WebSearchRequests,
			Fast:              u.Fast,
		})
	}
}

// routingState is the immutable value the RoutingStateHandle publishes
// behind its atomic.Pointer - the router's ORG-LAYER effective identity
// as of the last construction or hot-reload. Swapped whole, never
// mutated in place, so a reader always sees a coherent triple.
type routingState struct {
	version int64  // org routing-policy version composed into the live policy
	hash    string // org-layer running identity (routing.Policy.Hash(), 16-hex)
	mode    string // advise|enforce (normalized by the reader)
}

// RoutingStateHandle exposes the router's ORG-LAYER effective state for
// the P0-6 effective-policy-state reporter (docs/plans/plane-a-p0-6-
// effective-policy-state-plan.md §4.2) AND carries the P0-7 hot-reload
// closure. It is a LIVE carrier: wireRouting publishes the initial
// routingState and liveRouter.ReloadOrgPolicy publishes a new one after
// an accepted org policy is applied to the live engine, so the reporter
// observes the router flip pending_restart -> effective with no daemon
// restart. Reads are lock-free (atomic.Pointer load).
//
// effectiveHash is the ORG-LAYER running identity captured ONLY when an
// org routing policy is composed into the live policy (version > 0).
// With NO org policy composed (local-only routing), version is 0 and
// hash is EMPTY - a purely-local routing config has no org desired-state
// to report, so the reader resolves it to none/no_policy (R5-B2), never
// the local-config hash.
type RoutingStateHandle struct {
	state atomic.Pointer[routingState]
	// reload is the P0-7 hot-reload closure (§4.4 decision A), set by
	// wireRouting to liveRouter.ReloadOrgPolicy. Unexported-set,
	// exported-invoke via Reload; nil-safe.
	reload func(context.Context) error
	// setME forwards to liveRouter.SetManagedEnforce (Arc 4 P3b). Set by
	// wireRouting; invoked via SetManagedEnforce from start.go once the
	// governance handle exists. nil-safe.
	setME func(func() bool)
}

// SetManagedEnforce injects the routing managed-enforce predicate (Arc 4 P3b)
// onto the live router after buildProxy, where the governance handle exists.
// Nil-safe: a build with routing off (setME unset) ignores it.
func (h *RoutingStateHandle) SetManagedEnforce(fn func() bool) {
	if h != nil && h.setME != nil {
		h.setME(fn)
	}
}

// store publishes a new routingState (construction + hot-reload).
func (h *RoutingStateHandle) store(s routingState) { h.state.Store(&s) }

// RunningVersion returns the org routing-policy version composed into the live
// policy (0 = local-only, no org policy running).
func (h *RoutingStateHandle) RunningVersion() int64 {
	if s := h.state.Load(); s != nil {
		return s.version
	}
	return 0
}

// EffectiveHash returns the org-layer running identity (16-hex) when an org
// policy is composed, else "".
func (h *RoutingStateHandle) EffectiveHash() string {
	if s := h.state.Load(); s != nil {
		return s.hash
	}
	return ""
}

// Mode returns the router's raw mode token (advise|enforce); the reader
// normalizes advise->observe.
func (h *RoutingStateHandle) Mode() string {
	if s := h.state.Load(); s != nil {
		return s.mode
	}
	return ""
}

// Snapshot returns the whole org-layer state triple in ONE atomic load
// (P0-7 SHOULD-FIX 4). The P0-6 reader uses this so a reload between
// RunningVersion/EffectiveHash/Mode cannot yield a mixed report
// (e.g. version=2 with hash from v1). ok=false when nothing has been
// published yet (routing off / not yet wired) - callers treat that as
// the zero triple.
func (h *RoutingStateHandle) Snapshot() (version int64, hash, mode string, ok bool) {
	if h == nil {
		return 0, "", "", false
	}
	s := h.state.Load()
	if s == nil {
		return 0, "", "", false
	}
	return s.version, s.hash, s.mode, true
}

// Reload invokes the P0-7 hot-reload closure (§4.4). Nil-safe on both a
// nil handle and an unset closure (routing off / not yet wired), so the
// start.go reload-sink registration is unconditional.
func (h *RoutingStateHandle) Reload(ctx context.Context) error {
	if h == nil || h.reload == nil {
		return nil
	}
	return h.reload(ctx)
}
