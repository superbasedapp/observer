//go:build !sbo_omit_security

package main

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// TestSecurityRetentionPlanPerProject (lane SEC-P4 decision 10): two
// projects, one whose section keeps findings 730 days and one unmatched;
// the node keeps 90. The floored project is pruned on its own at 730 and
// left out of the node-wide prune; the unmatched directory takes the
// org-wide floor (here none beyond the node's). An org-wide floor that
// keeps findings longer than the node raises the node-wide days, and the
// project at the same value is not special.
func TestSecurityRetentionPlanPerProject(t *testing.T) {
	local := config.DefaultSecurityConfig()
	local.Retention.Days = 90
	withProjectSections(t, false, true, local, map[string]guard.ProjectFamilyLoad{
		"/floored":   matched(guard.ProjectFamilySet{OrgProjectID: "X", Members: []orgcontract.ProjectFamilyMember{sectionMember(t, 3, `{"require":{"finding_retention_days":730}}`, "X")}}),
		"/unmatched": {InForce: true, State: projectmatch.StateUnmatched},
	})
	roots := func(context.Context) ([]string, error) { return []string{"/floored", "/unmatched"}, nil }
	plan := securityRetentionPlanFor(context.Background(), local, roots)
	if plan.Node != 90 || len(plan.Projects) != 1 || plan.Projects[secposture.ProjectRootHash("/floored")] != 730 {
		t.Fatalf("plan %+v, want node 90 and the floored project at 730", plan)
	}
	installFloor(t, `{"require":{"finding_retention_days":730}}`, 1, true)
	plan = securityRetentionPlanFor(context.Background(), local, roots)
	if plan.Node != 730 || len(plan.Projects) != 0 {
		t.Fatalf("org-wide 730: plan %+v, want node 730 and nothing special", plan)
	}
	// A project that keeps forever (0) is the strictest.
	withProjectSections(t, false, true, local, map[string]guard.ProjectFamilyLoad{
		"/forever": matched(guard.ProjectFamilySet{OrgProjectID: "Y", Members: []orgcontract.ProjectFamilyMember{sectionMember(t, 3, `{"require":{"finding_retention_days":0}}`, "Y")}}),
	})
	plan = securityRetentionPlanFor(context.Background(), local, func(context.Context) ([]string, error) { return []string{"/forever"}, nil })
	if d, ok := plan.Projects[secposture.ProjectRootHash("/forever")]; !ok || d != 0 {
		t.Fatalf("keep-forever project: plan %+v", plan)
	}
}
