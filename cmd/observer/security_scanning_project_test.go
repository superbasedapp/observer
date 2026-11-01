//go:build !sbo_omit_security

package main

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam/securityscanning"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
)

// withProjectSections binds the node as withSecurityScanningNode does, with
// security.scanning accepted (and in effect when inEffect), and the guard's
// project read replaced by loads keyed by directory.
func withProjectSections(t *testing.T, managed, inEffect bool, sc config.SecurityConfig, loads map[string]guard.ProjectFamilyLoad) {
	t.Helper()
	withSecurityScanningNode(t, managed, sc, "security.deps")
	secScanning.mu.Lock()
	secScanning.load = func(context.Context) (securityScanningBase, error) {
		return securityScanningBase{Managed: managed, Security: sc, FamilyAccepted: true, FamilyInEffect: inEffect}, nil
	}
	secScanning.baseOK = false
	secScanning.mu.Unlock()
	saved := securityProjectFamiliesAt
	securityProjectFamiliesAt = func(root string) guard.ProjectFamilyLoad { return loads[root] }
	t.Cleanup(func() { securityProjectFamiliesAt = saved })
}

// sectionMember is a security.scanning member as the envelope carries it.
func sectionMember(t *testing.T, version int64, body string, projects ...string) orgcontract.ProjectFamilyMember {
	t.Helper()
	_, canon, err := securityscanning.CompileBody([]byte(body), 0)
	if err != nil {
		t.Fatal(err)
	}
	return orgcontract.ProjectFamilyMember{
		Family: "security.scanning", Version: version, Projects: projects,
		Body: string(canon), BodyHash: orgcontract.ProjectFamilyBodyHash(string(canon)),
	}
}

func matched(sets ...guard.ProjectFamilySet) guard.ProjectFamilyLoad {
	return guard.ProjectFamilyLoad{InForce: true, State: projectmatch.StateMatched, Projects: sets}
}

// TestSecurityFloorsAppliedAt is lane sec-p3 milestone 2, one test per cell:
// the org-wide floor first, then every matched project's sections merged
// raise-only (strictest of several projects); an unmatched, unknown or
// unavailable directory gets the org-wide floor only; an inert family,
// a body that is not canonical and a section that cannot merge apply
// nothing; managed-only keys follow the tenancy (security plan 7.3).
func TestSecurityFloorsAppliedAt(t *testing.T) {
	local := config.DefaultSecurityConfig() // retention 365, online on
	offline := local
	offline.Deps.Online = false
	forbid := `{"allow":{"online_checks":"forbidden"}}`
	keep90 := `{"require":{"finding_retention_days":730}}`
	cases := []struct {
		name          string
		managed       bool
		inEffect      bool
		base          config.SecurityConfig
		orgWide       string
		load          func(t *testing.T) guard.ProjectFamilyLoad
		wantOnline    bool
		wantRetention int
		wantStates    []string
	}{
		{"matched project forbids online", false, true, local, "", func(t *testing.T) guard.ProjectFamilyLoad {
			return matched(guard.ProjectFamilySet{OrgProjectID: "X", Members: []orgcontract.ProjectFamilyMember{sectionMember(t, 3, forbid, "X")}})
		}, false, 365, []string{securitySectionApplied}},
		{"unmatched directory: org-wide only", false, true, local, keep90, func(*testing.T) guard.ProjectFamilyLoad {
			return guard.ProjectFamilyLoad{InForce: true, State: projectmatch.StateUnmatched}
		}, true, 730, nil},
		{"unknown directory: org-wide only", false, true, local, keep90, func(*testing.T) guard.ProjectFamilyLoad {
			return guard.ProjectFamilyLoad{InForce: true, State: projectmatch.StateUnknown}
		}, true, 730, nil},
		{"no v3 delivery: org-wide only", false, true, local, "", func(*testing.T) guard.ProjectFamilyLoad { return guard.ProjectFamilyLoad{} }, true, 365, nil},
		{"envelope unavailable: section unknown, org-wide only", false, true, local, keep90, func(*testing.T) guard.ProjectFamilyLoad {
			return matched(guard.ProjectFamilySet{OrgProjectID: "X", Unavailable: true})
		}, true, 730, []string{securitySectionUnknown}},
		{"project raises over the org-wide floor", false, true, local, forbid, func(t *testing.T) guard.ProjectFamilyLoad {
			return matched(guard.ProjectFamilySet{OrgProjectID: "X", Members: []orgcontract.ProjectFamilyMember{sectionMember(t, 3, keep90, "X")}})
		}, false, 730, []string{securitySectionApplied}},
		{"project never lowers the org-wide floor", false, true, local, `{"require":{"finding_retention_days":0}}`, func(t *testing.T) guard.ProjectFamilyLoad {
			return matched(guard.ProjectFamilySet{OrgProjectID: "X", Members: []orgcontract.ProjectFamilyMember{sectionMember(t, 3, `{"require":{"finding_retention_days":90}}`, "X")}})
		}, true, 0, []string{securitySectionApplied}},
		{"two matched projects: strictest", false, true, local, "", func(t *testing.T) guard.ProjectFamilyLoad {
			return matched(
				guard.ProjectFamilySet{OrgProjectID: "X", Members: []orgcontract.ProjectFamilyMember{sectionMember(t, 3, `{"require":{"finding_retention_days":730}}`, "X")}},
				guard.ProjectFamilySet{OrgProjectID: "Y", Members: []orgcontract.ProjectFamilyMember{sectionMember(t, 4, `{"require":{"finding_retention_days":0}}`, "Y"), sectionMember(t, 5, forbid, "Y")}},
			)
		}, false, 0, []string{securitySectionApplied, securitySectionApplied, securitySectionApplied}},
		{"family not preauthorized: inert", false, false, local, "", func(t *testing.T) guard.ProjectFamilyLoad {
			return matched(guard.ProjectFamilySet{OrgProjectID: "X", Members: []orgcontract.ProjectFamilyMember{sectionMember(t, 3, forbid, "X")}})
		}, true, 365, []string{securitySectionInert}},
		{"a body that is not canonical is refused", false, true, local, "", func(t *testing.T) guard.ProjectFamilyLoad {
			m := sectionMember(t, 3, forbid, "X")
			m.Body = `{ "allow": {"online_checks": "forbidden"}, "version": 1 }`
			return matched(guard.ProjectFamilySet{OrgProjectID: "X", Members: []orgcontract.ProjectFamilyMember{m}})
		}, true, 365, []string{securitySectionRefused}},
		{"a section that cannot merge is refused, the org-wide floor kept", true, true, offline, `{"require":{"online_checks":"required"}}`, func(t *testing.T) guard.ProjectFamilyLoad {
			return matched(guard.ProjectFamilySet{OrgProjectID: "X", Members: []orgcontract.ProjectFamilyMember{sectionMember(t, 3, forbid, "X")}})
		}, true, 365, []string{securitySectionRefused}},
		{"managed-only key on an individual node: not applied", false, true, offline, "", func(t *testing.T) guard.ProjectFamilyLoad {
			return matched(guard.ProjectFamilySet{OrgProjectID: "X", Members: []orgcontract.ProjectFamilyMember{sectionMember(t, 3, `{"require":{"online_checks":"required"}}`, "X")}})
		}, false, 365, []string{securitySectionApplied}},
		{"managed-only key on a managed node: applied", true, true, offline, "", func(t *testing.T) guard.ProjectFamilyLoad {
			return matched(guard.ProjectFamilySet{OrgProjectID: "X", Members: []orgcontract.ProjectFamilyMember{sectionMember(t, 3, `{"require":{"online_checks":"required"}}`, "X")}})
		}, true, 365, []string{securitySectionApplied}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withProjectSections(t, c.managed, c.inEffect, c.base, map[string]guard.ProjectFamilyLoad{"/repo": c.load(t)})
			if c.orgWide != "" {
				installFloor(t, c.orgWide, 1, true)
			}
			got := securityFloorsAppliedAt(c.base, "/repo")
			if got.Deps.Online != c.wantOnline || got.Retention.Days != c.wantRetention {
				t.Fatalf("online=%v retention=%d, want %v %d", got.Deps.Online, got.Retention.Days, c.wantOnline, c.wantRetention)
			}
			var states []string
			for _, s := range secScanning.projectView("/repo").Sections {
				states = append(states, s.State)
			}
			if strings.Join(states, ",") != strings.Join(c.wantStates, ",") {
				t.Fatalf("section states = %v, want %v", states, c.wantStates)
			}
			// The org-wide seam and another directory never see a project
			// section.
			if org := securityFloorsApplied(c.base); !reflect.DeepEqual(securityFloorsAppliedAt(c.base, "/elsewhere"), org) || !reflect.DeepEqual(securityFloorsAppliedAt(c.base, ""), org) {
				t.Fatal("a project section leaked outside its directory")
			}
		})
	}
}

// TestSecurityProjectStatusLines names the per-directory state and marks a
// node-wide key as such rather than "applied" alone.
func TestSecurityProjectStatusLines(t *testing.T) {
	member := func(body string) orgcontract.ProjectFamilyMember { return sectionMember(t, 7, body, "X") }
	withProjectSections(t, false, true, config.DefaultSecurityConfig(), map[string]guard.ProjectFamilyLoad{
		"/repo":      matched(guard.ProjectFamilySet{OrgProjectID: "X", Members: []orgcontract.ProjectFamilyMember{member(`{"allow":{"online_checks":"forbidden"},"require":{"finding_retention_days":730}}`)}}),
		"/unmatched": {InForce: true, State: projectmatch.StateUnmatched},
		"/unknown":   {InForce: true, State: projectmatch.StateUnknown},
	})
	out := strings.Join(securityProjectStatusLines("/repo"), "\n")
	for _, want := range []string{"project X section v7: applied", "allow.online_checks: applied (floor forbidden)", "require.finding_retention_days: applied (floor 730)"} {
		if !strings.Contains(out, want) {
			t.Fatalf("status lacks %q:\n%s", want, out)
		}
	}
	// Retention is applied per project since lane SEC-P4 decision 10, so it
	// carries no node-wide note.
	if strings.Contains(out, "require.finding_retention_days: applied (floor 730): node-wide") {
		t.Fatalf("retention still reads node-wide:\n%s", out)
	}
	// SEC-P3 merge finding 3 reported a project section raising the commit
	// gate as not built per project; since lane SEC-P4 decision 9 the floor
	// is applied per project on a managed node (signed into that project's
	// posture), so it reads applied there.
	withProjectSections(t, true, true, config.DefaultSecurityConfig(), map[string]guard.ProjectFamilyLoad{
		"/gate": matched(guard.ProjectFamilySet{OrgProjectID: "X", Members: []orgcontract.ProjectFamilyMember{member(`{"require":{"commit_gate":"quick_scan"}}`)}}),
	})
	gate := ""
	for _, l := range securityProjectStatusLines("/gate") {
		if strings.Contains(l, "require.commit_gate") {
			gate = l
		}
	}
	if strings.Contains(gate, "not_built") || !strings.Contains(gate, "applied (floor quick_scan)") || strings.Contains(gate, "node-wide") {
		t.Fatalf("commit-gate line = %q, want applied per project", gate)
	}
	withProjectSections(t, false, true, config.DefaultSecurityConfig(), map[string]guard.ProjectFamilyLoad{
		"/unmatched": {InForce: true, State: projectmatch.StateUnmatched},
		"/unknown":   {InForce: true, State: projectmatch.StateUnknown},
	})
	if l := securityProjectStatusLines("/unmatched"); len(l) != 1 || !strings.Contains(l[0], "matched no org project") {
		t.Fatalf("unmatched = %v", l)
	}
	if l := securityProjectStatusLines("/unknown"); len(l) != 1 || !strings.Contains(l[0], "unknown") {
		t.Fatalf("unknown = %v", l)
	}
	if l := securityProjectStatusLines("/not-v3"); l != nil {
		t.Fatalf("no v3 delivery = %v", l)
	}
}

// TestSecurityFamilySectionStatus is one row per cell of the node's family
// status (lane sec-p3 milestone 3): the guard's project status, except a
// body this node cannot compile to its bytes (refused), a family not
// preauthorized (inert) and a section that cannot merge over the org-wide
// floor (refused); a list beyond the wire's bound is cut and flagged.
func TestSecurityFamilySectionStatus(t *testing.T) {
	forbid := `{"allow":{"online_checks":"forbidden"}}`
	cases := []struct {
		name     string
		inEffect bool
		orgWide  string
		body     string
		mangle   bool
		status   string
		want     string
	}{
		{"applied", true, "", forbid, false, orgcontract.ProjectSectionApplied, orgcontract.ProjectFamilyApplied},
		{"not matched", true, "", forbid, false, orgcontract.ProjectSectionNotMatched, orgcontract.ProjectFamilyNotMatched},
		{"unknown stays unknown", true, "", forbid, false, orgcontract.ProjectSectionUnknown, orgcontract.ProjectFamilyUnknown},
		{"not canonical: refused", true, "", forbid, true, orgcontract.ProjectSectionApplied, orgcontract.ProjectFamilyRefused},
		{"not preauthorized: inert", false, "", forbid, false, orgcontract.ProjectSectionApplied, orgcontract.ProjectFamilyInert},
		{"cannot merge: refused", true, `{"require":{"online_checks":"required"}}`, forbid, false, orgcontract.ProjectSectionApplied, orgcontract.ProjectFamilyRefused},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withProjectSections(t, true, c.inEffect, config.DefaultSecurityConfig(), nil)
			if c.orgWide != "" {
				installFloor(t, c.orgWide, 1, true)
			}
			m := sectionMember(t, 3, c.body, "X")
			if c.mangle {
				m.Body = " " + m.Body
			}
			got, truncated := secScanning.familyStatus([]guard.ProjectFamilySection{{OrgProjectID: "X", Status: c.status, Member: m}})
			if truncated || len(got) != 1 || got[0].Status != c.want || got[0].Version != 3 || got[0].Family != "security.scanning" {
				t.Fatalf("status = %+v (truncated %v), want %s", got, truncated, c.want)
			}
		})
	}
	withProjectSections(t, false, true, config.DefaultSecurityConfig(), nil)
	var many []guard.ProjectFamilySection
	for i := 0; i < orgcontract.MaxProjectMappingProjects+5; i++ {
		many = append(many, guard.ProjectFamilySection{OrgProjectID: "X", Status: orgcontract.ProjectSectionApplied, Member: sectionMember(t, int64(i+1), forbid, "X")})
	}
	many = append(many, guard.ProjectFamilySection{OrgProjectID: "bad id", Status: orgcontract.ProjectSectionApplied, Member: sectionMember(t, 1, forbid, "bad id")})
	got, truncated := secScanning.familyStatus(many)
	if !truncated || len(got) != orgcontract.MaxProjectMappingProjects || !orgcontract.ValidProjectFamilyStatus(got) {
		t.Fatalf("cut list: %d entries, truncated %v", len(got), truncated)
	}
}
