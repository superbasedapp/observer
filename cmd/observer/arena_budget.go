package main

import "context"

// arenaBudgetAdmissionSeam binds Agent Arena process starts to the same cold
// managed-budget admission used by command launchers. Arena's active backend
// is not proven at this boundary, so managed hard budgets conservatively
// refuse the process before it starts.
//
// NO PROCESS EVIDENCE IS AVAILABLE HERE, and that is structural rather than an
// omission: what Arena starts is Observer's OWN launcher for the candidate
// tool, not the vendor binary, and the seam it is installed behind
// (internal/arena.Driver.Admission) carries a tool name and a proxy URL only.
// The vendor process that actually spends is started one level down, by that
// inner `observer <tool>` launcher, which runs this same gate with its real
// executable, argv and route evidence. So process-cutoff recovery belongs
// there; this boundary stays the conservative outer check.
func arenaBudgetAdmissionSeam(configPath string) func(context.Context, string, string) error {
	return func(ctx context.Context, tool, _ string) error {
		return enforceBudgetControlledLaunch(ctx, configPath, tool,
			budgetLaunchEvidence{Route: budgetLaunchRouteUnknown})
	}
}
