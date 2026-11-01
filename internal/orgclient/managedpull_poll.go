package orgclient

import (
	"context"
	"errors"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// managedpull_poll.go is the shared poll step of the module managed-pull kit
// (roadmap F0-7; lane SBX-P1C). Before it nothing called FetchManagedPull:
// the kit's fetch, ladder and cache were built and tested, but no cycle
// polled a rail. This step is that cycle, for every rail of
// orgcontract.ManagedPullRails at once, so a module that adds a rail (the
// sandbox module's GET /api/agent/sandbox, the security module's GET
// /api/agent/security) registers a sink and gets polled, never a second
// loop.
//
// The rules it keeps:
//   - a rail with no registered sink makes NO request. A node whose sandbox
//     module is inactive or compiled out registers no sandbox sink, so an
//     install that never uses a rail sends nothing for it;
//   - the consent for a rail (managed tenancy, and the rail's Authority in
//     the honoured grant) comes from the caller's one consent resolver,
//     resolved LIVE per poll, so a revoked authority stops applying at the
//     next cycle; this package never decides which token a rail needs;
//   - a rail without that consent makes NO request either (SBX-P1C merge
//     finding 8): an individual node, or a managed node whose grant lacks
//     the rail's authority, only reports its stored document to the sink,
//     which is inert under that consent. A body it could not apply is never
//     fetched, so such a node sends nothing for the rail;
//   - the step runs on the push cycle beside refreshBudgetRails (no new
//     timer, host or connection), and the cycle cadence is the retry with
//     backoff the ladder asks for after a 5xx or a transport error.

// ManagedPullSink receives every poll's outcome for one rail. It is called
// with an outcome whose InForce is false whenever the managed values must
// not apply (not enrolled, not preauthorized, expired, cleared), so the sink
// can always drop back to local values from the outcome alone.
type ManagedPullSink func(ManagedPullOutcome)

// ManagedPullConsentFunc resolves a rail's consent from the honoured grant.
type ManagedPullConsentFunc func(ctx context.Context, rail orgcontract.ManagedPullRail) ManagedPullConsent

// managedPullRailSet is the client's registration of rail sinks. One owner:
// set once by SetManagedPullRails, read by the poll step.
type managedPullRailSet struct {
	mu      sync.RWMutex
	sinks   map[string]ManagedPullSink
	consent ManagedPullConsentFunc
}

// SetManagedPullRails registers the sinks of the rails this node consumes
// (rail name to sink) and the consent resolver every poll asks. A rail name
// that is not in orgcontract.ManagedPullRails is ignored. Calling it again
// replaces the registration. A nil consent resolver means no consent: every
// body stays inert.
func (c *Client) SetManagedPullRails(consent ManagedPullConsentFunc, sinks map[string]ManagedPullSink) {
	if c == nil {
		return
	}
	reg := make(map[string]ManagedPullSink, len(sinks))
	for name, sink := range sinks {
		if _, ok := orgcontract.LookupManagedPullRail(name); ok && sink != nil {
			reg[name] = sink
		}
	}
	c.managedPullRails.mu.Lock()
	c.managedPullRails.sinks = reg
	c.managedPullRails.consent = consent
	c.managedPullRails.mu.Unlock()
}

// managedPullTarget is one rail the step will poll.
type managedPullTarget struct {
	rail orgcontract.ManagedPullRail
	sink ManagedPullSink
}

// managedPullTargets walks the closed rail table (never the map, so the poll
// order is the table's) and keeps the rails with a sink.
func (c *Client) managedPullTargets() ([]managedPullTarget, ManagedPullConsentFunc) {
	c.managedPullRails.mu.RLock()
	defer c.managedPullRails.mu.RUnlock()
	var out []managedPullTarget
	for _, rail := range orgcontract.ManagedPullRails {
		if sink := c.managedPullRails.sinks[rail.Name]; sink != nil {
			out = append(out, managedPullTarget{rail: rail, sink: sink})
		}
	}
	return out, c.managedPullRails.consent
}

func resolveManagedPullConsent(ctx context.Context, fn ManagedPullConsentFunc, rail orgcontract.ManagedPullRail) ManagedPullConsent {
	if fn == nil {
		return ManagedPullConsent{}
	}
	return fn(ctx, rail)
}

// pollManagedPullRails is the push-cycle step: one FetchManagedPull per rail
// with a sink. A fetch error other than not-enrolled changed nothing in the
// cache (FetchManagedPull's contract), so the sink is not told and keeps what
// it applies; a not-enrolled node tells every sink, which then drops back to
// local values.
func (c *Client) pollManagedPullRails(ctx context.Context) {
	if c == nil {
		return
	}
	targets, consent := c.managedPullTargets()
	for _, t := range targets {
		if ctx.Err() != nil {
			return
		}
		granted := resolveManagedPullConsent(ctx, consent, t.rail)
		if !granted.Managed || !granted.HoldsAuthority {
			c.reportStoredManagedPull(ctx, t, granted)
			continue
		}
		out, err := c.FetchManagedPull(ctx, t.rail.Name, granted)
		switch {
		case err == nil, errors.Is(err, ErrNotEnrolled):
			if err != nil {
				out = ManagedPullOutcome{Rail: t.rail.Name, State: ManagedPullStateNotEnrolled}
			}
			t.sink(out)
		case errors.Is(err, context.Canceled):
			return
		default:
			c.logger.Warn("org managed pull: fetch failed, keeping the stored document", "rail", t.rail.Name, "err", err)
		}
	}
}

// reportStoredManagedPull tells a rail's sink its stored document under a
// consent that cannot apply it, without a request: the sink drops back to
// local values (a revoked authority stops applying at the next cycle).
func (c *Client) reportStoredManagedPull(ctx context.Context, t managedPullTarget, granted ManagedPullConsent) {
	out, err := c.LoadPersistedManagedPull(ctx, t.rail.Name, granted)
	switch {
	case err == nil:
	case errors.Is(err, ErrNotEnrolled):
		out = ManagedPullOutcome{Rail: t.rail.Name, State: ManagedPullStateNotEnrolled}
	default:
		c.logger.Warn("org managed pull: could not load the stored document", "rail", t.rail.Name, "err", err)
		return
	}
	out.InForce = false
	t.sink(out)
}

// PrimeManagedPullRails reports every registered rail's stored document
// without a request (daemon start), re-verified against the pinned key, so a
// restart applies the last verified body until the first poll. Its state is
// never ok (nothing was fetched by this process).
func (c *Client) PrimeManagedPullRails(ctx context.Context) {
	if c == nil {
		return
	}
	targets, consent := c.managedPullTargets()
	for _, t := range targets {
		out, err := c.LoadPersistedManagedPull(ctx, t.rail.Name, resolveManagedPullConsent(ctx, consent, t.rail))
		if err != nil && !errors.Is(err, ErrNotEnrolled) {
			c.logger.Warn("org managed pull: could not load the stored document", "rail", t.rail.Name, "err", err)
			continue
		}
		t.sink(out)
	}
}
