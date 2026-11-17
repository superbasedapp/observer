//go:build !sbo_omit_terminals

package main

import (
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// launch_dashboard_secretmask.go is the dashboard's half of the opt-in workspace
// secret mask (security assessments depth plan, decision D32): the adapter
// reports a fresh launch's outcome to a dashboard that asks for it
// (dashapi.FreshLaunchDetailer), flattened to counts and closed reason words so
// no path leaves the daemon.

// CreateFreshDetailed is CreateFresh with what the launch reports beyond its
// handle: the workspace secret mask's outcome when the spec asked for it, and the
// sandbox backend that built the box when the launch was sandboxed.
func (a *launchManagerAdapter) CreateFreshDetailed(spec dashapi.FreshLaunchSpec) (dashapi.FreshLaunchResult, error) {
	res, _, err := a.createFresh(spec)
	if err != nil {
		return dashapi.FreshLaunchResult{}, err
	}
	return dashapi.FreshLaunchResult{Handle: res.Handle, SecretMask: dashSecretMaskOutcome(res.SecretMask), Backend: res.Backend}, nil
}

// dashSecretMaskOutcome flattens the application service's outcome onto the
// dashboard's: the files hidden, whether the walk was complete and, for the
// places it was not, the count (listed gaps plus the ones past the list) and a
// count per closed reason word. nil in, nil out.
func dashSecretMaskOutcome(o *termsvc.SecretMaskOutcome) *dashapi.SecretMaskOutcome {
	if o == nil {
		return nil
	}
	out := &dashapi.SecretMaskOutcome{Masked: o.Masked, Complete: o.Complete, Gaps: len(o.Gaps) + o.GapsDropped}
	for _, g := range o.Gaps {
		if out.Reasons == nil {
			out.Reasons = map[string]int{}
		}
		out.Reasons[g.Reason]++
	}
	return out
}

// Compile-time proof the adapter offers the extension.
var _ dashapi.FreshLaunchDetailer = (*launchManagerAdapter)(nil)
