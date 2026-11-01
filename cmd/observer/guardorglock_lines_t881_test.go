package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
)

// TestGuardOrgLockLinesNamePinsAndTheBundleCause pins the `observer guard
// status` half of T-881 and T-889: a local value a governance pin replaced is
// listed as OVERRIDDEN beside the floor's, and the "Org bundle:" line says
// what is actually wrong with the file.
func TestGuardOrgLockLinesNamePinsAndTheBundleCause(t *testing.T) {
	lock := config.GuardOrgLock{
		State: "valid", TenancyKnown: true, Managed: true,
		Pinned:     []string{"guard.enabled: local false, organization pin true"},
		Overridden: []string{"guard.prompt.mode: local warn, organization floor redact"},
	}
	cases := []struct {
		name string
		st   guard.OrgLockStatus
		want []string
	}{
		{"clean bundle", guard.OrgLockStatus{}, nil},
		{
			"deleted bundle, last verified layer",
			guard.OrgLockStatus{BundleTampered: true, LastVerifiedInUse: true, BundleProblem: "is missing"},
			[]string{"Org bundle:   the cached bundle is missing - enforcing the last verified org layer"},
		},
		{
			"edited bundle, last verified layer",
			guard.OrgLockStatus{BundleTampered: true, LastVerifiedInUse: true, BundleProblem: "does not verify"},
			[]string{"Org bundle:   the cached bundle does not verify - enforcing the last verified org layer"},
		},
		{
			"deleted bundle, no verified copy",
			guard.OrgLockStatus{BundleTampered: true, Unverifiable: true, BundleProblem: "is missing"},
			[]string{"Org bundle:   the cached bundle is missing and no verified copy is held - local approvals are refused for every rule"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := guardOrgLockLines(lock, tc.st)
			want := append([]string{
				"Org lock:     managed node - the organization's guard floor is in force",
				"OVERRIDDEN:   guard.enabled: local false, organization pin true (set by organization policy; the local value does not apply)",
				"OVERRIDDEN:   guard.prompt.mode: local warn, organization floor redact (set by organization policy; the local value does not apply)",
			}, tc.want...)
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Fatalf("lines =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
		})
	}
}
