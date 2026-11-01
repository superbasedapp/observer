//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
)

// TestDepsProjectDatabaseRefusal (lane SEC-P4 decision 10): the node keeps
// one advisory database. A project whose section narrows the sources to
// exclude where it comes from, or asks for a younger database than the
// node-wide floor, reads its dependency scans unknown:
// advisory_database_not_allowed; another project, an unmatched directory
// and a project whose narrowed set still holds the source are unaffected.
// A linked worktree reads its main repository's sections (P-041).
func TestDepsProjectDatabaseRefusal(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	main := t.TempDir()
	if r, err := filepath.EvalSymlinks(main); err == nil {
		main = r
	}
	gitIn(t, main, "init", "-q")
	gitIn(t, main, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "--allow-empty", "-m", "one")
	wt := filepath.Join(t.TempDir(), "wt")
	gitIn(t, main, "worktree", "add", "-q", "--detach", wt)

	local := config.DefaultSecurityConfig()
	member := func(id, body string) guard.ProjectFamilyLoad {
		return matched(guard.ProjectFamilySet{OrgProjectID: id, Members: []orgcontract.ProjectFamilyMember{sectionMember(t, 3, body, id)}})
	}
	withProjectSections(t, false, true, local, map[string]guard.ProjectFamilyLoad{
		main:            member("X", `{"allow":{"scanner_sources":["org_mirror"]}}`),
		"/age":          member("Y", `{"require":{"max_advisory_db_age_h":24}}`),
		"/still-allows": member("Z", `{"allow":{"scanner_sources":["vendor_release","org_mirror"]}}`),
		"/unmatched":    {InForce: true, State: projectmatch.StateUnmatched},
	})
	for _, tc := range []struct {
		root string
		want string
	}{
		{main, depsReasonDatabaseNotAllowed},
		{wt, depsReasonDatabaseNotAllowed},
		{"/age", depsReasonDatabaseNotAllowed},
		{"/still-allows", ""},
		{"/unmatched", ""},
	} {
		if got := depsProjectDatabaseRefusal(local, tc.root, "vendor_release"); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.root, got, tc.want)
		}
	}
	// The node-wide age floor as strict as the project's: met.
	installFloor(t, `{"require":{"max_advisory_db_age_h":24}}`, 1, true)
	if got := depsProjectDatabaseRefusal(local, "/age", "vendor_release"); got != "" {
		t.Errorf("node-wide floor as strict: %q", got)
	}
}
