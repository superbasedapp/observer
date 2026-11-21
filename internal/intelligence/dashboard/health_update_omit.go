//go:build sbo_omit_org_update

package dashboard

// updateTerminalOmittedReason is what a build without the self-update
// component (org.update) says on the Settings > Health update card: it has
// no install-method detection, so it never guesses an update command.
const updateTerminalOmittedReason = "This build does not include the self-update component, so it cannot tell how this copy was installed. Update it the way you installed it, or from https://superbased.app/download."

// runningUpdatePlan is never available in this build. A var for symmetry
// with health_update_plan.go, whose handler tests replace it.
var runningUpdatePlan = func() updateTerminalPlan {
	return updateTerminalPlan{Reason: updateTerminalOmittedReason}
}
