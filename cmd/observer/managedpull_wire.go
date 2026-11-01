package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// managedpull_wire.go wires the module managed-pull kit's shared poll step
// (orgclient.SetManagedPullRails, roadmap F0-7, lane SBX-P1C) onto the
// daemon's org client. Two tables, no switch on a rail name (CLAUDE.md #3,
// #5):
//
//   - managedPullConsentRows maps a rail's Authority token onto the govern
//     predicate that says the honoured grant holds it. A rail whose token has
//     no row has no consent: its body stays inert everywhere.
//   - managedPullConsumers is the registry of node consumers. A module's own
//     file registers its consumer from init() (the sandbox module in
//     sandbox_managed.go); a module compiled out registers nothing, and a
//     consumer whose module is not active on this node is skipped, so no
//     request is made for its rail.

// managedPullConsentRow is one authority token and its grant predicate.
type managedPullConsentRow struct {
	authority string
	holds     func(govern.Effective) bool
}

// managedPullConsentRows is the closed consent table, one row per rail
// authority of orgcontract.ManagedPullRails (pinned by a test).
var managedPullConsentRows = []managedPullConsentRow{
	{authority: govern.AuthorityEnforceSandbox, holds: govern.Effective.GrantsSandboxEnforcement},
	{authority: govern.AuthorityEnforceSecurity, holds: govern.Effective.GrantsSecurityEnforcement},
}

// managedPullConsent resolves one rail's consent from the honoured grant:
// managed tenancy under a live managed grant, and the rail's authority.
func managedPullConsent(eff govern.Effective, rail orgcontract.ManagedPullRail) orgclient.ManagedPullConsent {
	out := orgclient.ManagedPullConsent{Managed: eff.Managed && !eff.GrantRefused()}
	for _, row := range managedPullConsentRows {
		if row.authority == rail.Authority {
			out.HoldsAuthority = row.holds(eff)
			break
		}
	}
	return out
}

// managedPullConsumer is one module's node consumer of a rail.
type managedPullConsumer struct {
	// rail is the orgcontract.ManagedPullRails name.
	rail string
	// active says whether the consuming module runs on this node; false
	// means no sink is registered and the rail makes no request.
	active func(componentstate.Snapshot) bool
	// sink receives every poll's outcome.
	sink orgclient.ManagedPullSink
	// bind, when set, receives the live grant before the first prime (a
	// consumer that reads pins from it).
	bind func(governanceEffective)
}

// managedPullConsumers is filled from init() by each module's consumer file.
var managedPullConsumers []managedPullConsumer

// registerManagedPullConsumer adds a consumer (init time only).
func registerManagedPullConsumer(c managedPullConsumer) {
	managedPullConsumers = append(managedPullConsumers, c)
}

// managedPullSinks returns the sinks of the consumers active on this node.
func managedPullSinks(comps componentstate.Snapshot) map[string]orgclient.ManagedPullSink {
	sinks := map[string]orgclient.ManagedPullSink{}
	for _, c := range managedPullConsumers {
		if c.sink == nil || (c.active != nil && !c.active(comps)) {
			continue
		}
		sinks[c.rail] = c.sink
	}
	return sinks
}

// governanceEffective is what the consent resolver reads (the daemon's
// nodeGovernanceHandle in production, a fixed value in tests).
type governanceEffective interface {
	Effective(ctx context.Context) govern.Effective
}

// wireManagedPullRails registers the active consumers on the org client and
// primes each from its stored document. With no active consumer it registers
// nothing, so the push cycle makes no managed-pull request at all.
func wireManagedPullRails(ctx context.Context, client *orgclient.Client, comps componentstate.Snapshot, gov governanceEffective) {
	if client == nil {
		return
	}
	sinks := managedPullSinks(comps)
	if len(sinks) == 0 {
		return
	}
	for _, c := range managedPullConsumers {
		if c.bind != nil && sinks[c.rail] != nil {
			c.bind(gov)
		}
	}
	client.SetManagedPullRails(func(ctx context.Context, rail orgcontract.ManagedPullRail) orgclient.ManagedPullConsent {
		if gov == nil {
			return orgclient.ManagedPullConsent{}
		}
		return managedPullConsent(gov.Effective(ctx), rail)
	}, sinks)
	client.PrimeManagedPullRails(ctx)
}
