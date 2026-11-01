package guard

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
)

// familyEnvelope is f.envelope with family members bound by their digest.
func (f *orgProjectFixture) familyEnvelope(id, body string, members ...orgcontract.ProjectFamilyMember) orgcontract.PolicyBundle {
	env := f.envelope(id, body, f.epoch)
	env.Families = members
	pb := *env.ProjectBinding
	pb.FamiliesDigest = orgcontract.ProjectFamiliesDigest(members)
	env.ProjectBinding = &pb
	env.Signature = orgcontract.SignPolicyBundleEnvelope(f.priv, env)
	return env
}

func scanningMember(version int64, body string, projects ...string) orgcontract.ProjectFamilyMember {
	return orgcontract.ProjectFamilyMember{
		Family: "security.scanning", Version: version, Projects: projects,
		Body: body, BodyHash: orgcontract.ProjectFamilyBodyHash(body),
	}
}

// TestOrgProjectFamilies is lane sec-p3 milestone 2 on the guard: the family
// sections are loaded next to the rules, from the same decision and the same
// verified envelope. A matched root reads its projects' members; an
// unmatched root, a stale mapping and no v3 delivery read none; a forged
// member makes the project unavailable rather than applied; a linked
// worktree reads its main repository's match record (P-041).
func TestOrgProjectFamilies(t *testing.T) {
	body := `{"allow":{"online_checks":"forbidden"},"version":1}`
	f := newOrgProjectFixture(t, orgFloor, map[string]string{"X": projX, "Y": projY})
	f.put(f.layout.EnvelopePath("X"), f.familyEnvelope("X", projX, scanningMember(5, body, "X")))
	f.match("/home/u/x", "X")
	f.match("/home/u/xy", "X", "Y")
	f.match("/home/u/none")
	g := f.guard(false)

	got := g.OrgProjectFamilies("/home/u/x")
	if !got.InForce || got.State != projectmatch.StateMatched || len(got.Projects) != 1 || len(got.Projects[0].Members) != 1 || got.Projects[0].Members[0].Version != 5 {
		t.Fatalf("matched root = %+v", got)
	}
	both := g.OrgProjectFamilies("/home/u/xy")
	if len(both.Projects) != 2 || both.Projects[0].OrgProjectID != "X" || both.Projects[1].OrgProjectID != "Y" || len(both.Projects[1].Members) != 0 {
		t.Fatalf("two projects = %+v", both)
	}
	if none := g.OrgProjectFamilies("/home/u/none"); !none.InForce || none.State != projectmatch.StateUnmatched || len(none.Projects) != 0 {
		t.Fatalf("unmatched root = %+v", none)
	}

	// A member whose body was swapped after signing: the envelope no longer
	// verifies, so the project is unavailable and none of its members load.
	forged := f.familyEnvelope("X", projX, scanningMember(5, body, "X"))
	forged.Families[0].Body = `{"version":1}`
	forged.Families[0].BodyHash = orgcontract.ProjectFamilyBodyHash(forged.Families[0].Body)
	f.put(f.layout.EnvelopePath("X"), forged)
	g = f.guard(false)
	if got := g.OrgProjectFamilies("/home/u/x"); len(got.Projects) != 1 || !got.Projects[0].Unavailable || len(got.Projects[0].Members) != 0 {
		t.Fatalf("forged member = %+v", got)
	}

	// No v3 delivery: not in force.
	plain := newOrgProjectFixture(t, orgFloor, nil)
	delete(plain.files, orgBundlePath)
	if got := plain.guard(false).OrgProjectFamilies("/home/u/x"); got.InForce {
		t.Fatalf("no delivery = %+v", got)
	}
}

// TestOrgProjectFamiliesLinkedWorktree: a linked worktree's sections are its
// main repository's (the matcher keys the record by the identity root).
func TestOrgProjectFamiliesLinkedWorktree(t *testing.T) {
	main := gitRepo(t, "https://github.com/acme/widget.git")
	wt := makeWorktree(t, main)
	sub := filepath.Join(main, "pkg")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"require":{"finding_retention_days":730},"version":1}`
	f := newOrgProjectFixture(t, orgFloor, map[string]string{"X": projX})
	f.put(f.layout.EnvelopePath("X"), f.familyEnvelope("X", projX, scanningMember(9, body, "X")))
	f.match(main, "X")
	g := f.guard(false)
	for name, dir := range map[string]string{"main repository": main, "linked worktree": wt, "subdirectory": sub} {
		got := g.OrgProjectFamilies(dir)
		if got.State != projectmatch.StateMatched || len(got.Projects) != 1 || len(got.Projects[0].Members) != 1 {
			t.Errorf("%s: %+v", name, got)
		}
	}
}

// TestOrgProjectFamilySections: the per-section report's family half lists
// each member of every mapped project whose envelope verifies, with that
// project's status; a project with no verified envelope lists nothing.
func TestOrgProjectFamilySections(t *testing.T) {
	body := `{"allow":{"online_checks":"forbidden"},"version":1}`
	f := newOrgProjectFixture(t, orgFloor, map[string]string{"X": projX, "Y": projY, "Z": projY})
	f.put(f.layout.EnvelopePath("X"), f.familyEnvelope("X", projX, scanningMember(5, body, "X", "Y")))
	f.put(f.layout.EnvelopePath("Y"), f.familyEnvelope("Y", projY, scanningMember(5, body, "X", "Y"), scanningMember(6, body, "Y")))
	delete(f.files, f.layout.EnvelopePath("Z"))
	f.match("/home/u/x", "X")
	got := f.guard(false).OrgProjectFamilySections(time.Now(), f.listFixture)
	if len(got) != 3 {
		t.Fatalf("sections = %+v, want 3", got)
	}
	if got[0].OrgProjectID != "X" || got[0].Status != orgcontract.ProjectSectionApplied || got[0].Member.Version != 5 {
		t.Fatalf("X = %+v", got[0])
	}
	if got[1].OrgProjectID != "Y" || got[1].Status != orgcontract.ProjectSectionNotMatched || got[2].Member.Version != 6 {
		t.Fatalf("Y = %+v %+v", got[1], got[2])
	}
}
