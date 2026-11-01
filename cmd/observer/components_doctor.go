package main

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/componentsvc"
	"github.com/marmutapp/superbased-observer/internal/diag"
)

// components_doctor.go is the Components section of `observer doctor`
// (modular packaging plan 7.3, lane MP-DASH, T-661): compiled versus
// selected versus policy, the build's distro, selection problems
// (required-missing, unknown ids), signature status, and leftover vendor
// entries an inactive component still has in other tools' config. Every
// check is named "components.*", so `observer doctor components` scopes to
// the section. An install with no [components] block gets one OK line and
// nothing else changes.

// leftoverProbe dry-runs the teardown of inactive components and returns
// what it would remove (componentsvc.Service.RunTeardown with dryRun).
type leftoverProbe func(ctx context.Context, ids []string) ([]componentsvc.StepOutcome, error)

// componentsDoctorChecks builds the section from a resolved snapshot. probe
// may be nil (no leftover check).
func componentsDoctorChecks(ctx context.Context, snap componentstate.Snapshot, probe leftoverProbe) []diag.Check {
	v := componentStateView(snap)
	sel := fmt.Sprintf("%d of %d compiled components active", v.ActiveCount, v.CompiledCount)
	var out []diag.Check
	if !v.Configured {
		out = append(out, diag.Check{
			Name: "components.selection", Status: diag.StatusOK,
			Message: sel + " (" + unconfiguredSelectionPhrase(v) + ")",
			Details: []string{"Choose what runs " + components.WhereToChange("`observer components select|add|remove`") + "."},
		})
	} else {
		details := []string{"base: " + v.Base}
		if len(v.Add) > 0 {
			details = append(details, "added: "+strings.Join(v.Add, ", "))
		}
		if len(v.Remove) > 0 {
			details = append(details, "removed: "+strings.Join(v.Remove, ", "))
		}
		out = append(out, diag.Check{
			Name: "components.selection", Status: diag.StatusOK,
			Message: sel + " (base " + v.Base + ")", Details: details,
		})
	}
	if len(v.Issues) > 0 {
		out = append(out, diag.Check{
			Name: "components.selection-issues", Status: diag.StatusWarn,
			Message: fmt.Sprintf("%d problem(s) in the [components] selection", len(v.Issues)),
			Details: v.Issues,
		})
	}
	build := diag.Check{
		Name: "components.build", Status: diag.StatusOK,
		Message: fmt.Sprintf("this binary matches the %s distro (digest %s)", v.BinaryDistro, shortDigest(v.ComponentsDigest)),
	}
	if v.BinaryDistro == "custom" {
		build.Status = diag.StatusWarn
		build.Message = fmt.Sprintf("this binary's compiled set matches no prebuilt distro (digest %s)", shortDigest(v.ComponentsDigest))
		if om := components.Omitted(); len(om) > 0 {
			build.Details = []string{"compiled out: " + strings.Join(om, ", ")}
		}
	}
	out = append(out, build)
	out = append(out, componentsPolicyCheck(v))
	out = append(out, diag.Check{
		Name: "components.signature", Status: diag.StatusOK,
		Message: "not a vendor-signed distro build (signed distro builds arrive with the distro release pipeline)",
	})
	if probe == nil {
		return out
	}
	var withTeardown []string
	for _, id := range snap.Inactive() {
		// A component this build lacks wrote nothing from this binary and
		// cannot be turned back on here; its leftovers are not this build's
		// to report (T-732: capture.browser warned on a minimal build).
		if d, ok := snap.Decision(id); ok && d.State == components.StateAbsent {
			continue
		}
		if len(componentsvc.TeardownFor(id)) > 0 {
			withTeardown = append(withTeardown, id)
		}
	}
	if len(withTeardown) == 0 {
		return out
	}
	outs, err := probe(ctx, withTeardown)
	if err != nil {
		return append(out, diag.Check{
			Name: "components.leftovers", Status: diag.StatusWarn,
			Message: "could not check other tools' config for leftovers of inactive components: " + err.Error(),
		})
	}
	var left []string
	owners := map[string]bool{}
	for _, o := range outs {
		if o.Changed {
			for _, d := range o.Detail {
				left = append(left, fmt.Sprintf("%s (%s): %s", o.Target, o.Component, d))
			}
			owners[o.Component] = true
		}
		for _, n := range o.NeedsAttention {
			if o.Kind != componentsvc.StepManual {
				left = append(left, fmt.Sprintf("%s (%s): %s", o.Target, o.Component, n))
				owners[o.Component] = true
			}
		}
	}
	if len(left) == 0 {
		return append(out, diag.Check{
			Name: "components.leftovers", Status: diag.StatusOK,
			Message: "no Observer entries from inactive components remain in other tools' config",
		})
	}
	ids := make([]string, 0, len(owners))
	for id := range owners {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return append(out, diag.Check{
		Name: "components.leftovers", Status: diag.StatusWarn,
		Message: "inactive components still have entries in other tools' config: remove them " + components.WhereToChange("`observer components teardown "+strings.Join(ids, " ")+"`"),
		Details: left,
	})
}

// componentsPolicyCheck is the components.policy row: which component
// policy is in force (lane MP-GOV, plan 6.2) and, on an org-managed node, a
// warning when the local block tries to narrow it (ledger MODPKG-7, ruling
// D-434: ignored, never applied).
func componentsPolicyCheck(v componentstate.View) diag.Check {
	c := diag.Check{Name: "components.policy", Status: diag.StatusOK}
	switch {
	case v.OrgManaged:
		c.Message = fmt.Sprintf("managed by %s: %s", v.OrgName, managedSourcePhrase(v.GovernanceSource))
		c.Details = []string{"A local change may not narrow this machine; request a change from your organization."}
		if len(v.Ignored) > 0 {
			c.Status = diag.StatusWarn
			c.Message = fmt.Sprintf("managed by %s: the local [components] block tries to narrow this machine and is ignored", v.OrgName)
			c.Details = append([]string{"ignored: " + strings.Join(v.Ignored, "; ")}, c.Details...)
		}
	case v.GovernanceSource == "dormant":
		c.Message = "the organization's component policy is dormant (the enrolment grant expired, the identity changed or the node was offboarded): the local selection decides"
	default:
		c.Message = "no organization component policy applies: the local selection decides"
	}
	return c
}

// managedSources says, per nodecomponents source, what decides a managed
// node's components (T-739, D-548). The raw source used to be printed as
// "(policy source unauthorized)", which read as a fault on a properly
// managed node whose grant simply does not carry components.govern.
var managedSources = map[string]string{
	"policy":          "the organization's component policy decides which components run",
	"last_known_good": "the last component policy that verified decides which components run (the current one has expired or did not verify)",
	"initial_grant":   "the enrolment grant's initial component set decides which components run (no component policy received yet)",
	"legacy_pinned":   "this machine keeps the components it was running at enrolment (no component policy received yet)",
	"unauthorized":    "the enrolment does not let the organization choose components (no components.govern authority), so this machine keeps this build's set",
}

// managedSourcePhrase is the components.policy wording for a source.
func managedSourcePhrase(source string) string {
	if p, ok := managedSources[source]; ok {
		return p
	}
	return "the organization decides which components run"
}

// componentsDoctorChecksFor wires the section for a config path: the
// snapshot `observer components status` shows and the service's dry-run
// teardown as the leftover probe.
func componentsDoctorChecksFor(ctx context.Context, configPath string) []diag.Check {
	snap := componentSnapshotFor(configPath)
	var probe leftoverProbe
	if snap.Configured {
		if svc, err := newComponentsService(configPath, nil); err == nil {
			probe = func(ctx context.Context, ids []string) ([]componentsvc.StepOutcome, error) {
				return svc.RunTeardown(ctx, ids, true)
			}
		}
	}
	return componentsDoctorChecks(ctx, snap, probe)
}
