package guard

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
)

// listFixture lists the fixture's in-memory files under dir.
func (f *orgProjectFixture) listFixture(dir string) ([]string, error) {
	var out []string
	for p := range f.files {
		if filepath.Dir(p) == dir {
			out = append(out, filepath.Base(p))
		}
	}
	return out, nil
}

// TestProjectSectionTable has one row per rule of projectSectionTable.
func TestProjectSectionTable(t *testing.T) {
	cases := []struct {
		name string
		f    projectSectionFacts
		want string
	}{
		{"mapping not current", projectSectionFacts{mappingCurrent: false, matched: true}, orgcontract.ProjectSectionUnknown},
		{"envelope missing", projectSectionFacts{mappingCurrent: true, envelope: envelopeMissing, matched: true}, orgcontract.ProjectSectionNotDelivered},
		{"envelope invalid", projectSectionFacts{mappingCurrent: true, envelope: envelopeInvalid, matched: true}, orgcontract.ProjectSectionUnknown},
		{"matched", projectSectionFacts{mappingCurrent: true, matched: true}, orgcontract.ProjectSectionApplied},
		{"matched beside an unknown root", projectSectionFacts{mappingCurrent: true, matched: true, unknownRoot: true}, orgcontract.ProjectSectionApplied},
		{"an unknown root, not matched", projectSectionFacts{mappingCurrent: true, unknownRoot: true}, orgcontract.ProjectSectionUnknown},
		{"not matched", projectSectionFacts{mappingCurrent: true}, orgcontract.ProjectSectionNotMatched},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := projectSectionStatusOf(tc.f); got != tc.want {
				t.Fatalf("status = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestOrgProjectSectionStatus reads a real cache: X matched by a current
// record (applied), Y mapped and not matched, Z mapped with no envelope (not
// delivered), W with an envelope of another epoch (unknown); then the whole
// mapping expired (every section unknown), and a v2 node (nil).
func TestOrgProjectSectionStatus(t *testing.T) {
	f := newOrgProjectFixture(t, orgFloor, map[string]string{"X": projX, "Y": projY, "Z": projY, "W": projY})
	f.match("/home/u/x", "X")
	delete(f.files, f.layout.EnvelopePath("Z"))
	f.put(f.layout.EnvelopePath("W"), f.envelope("W", projY, f.epoch-1))
	// A stale record (another digest) names Y: it must not count.
	f.put(f.layout.MatchPath(projectmatch.RootHash("/home/u/y")), projectmatch.MatchFile{
		OrgProjectIDs: []string{"Y"}, Epoch: f.epoch, MappingDigest: "other", ValidUntil: time.Now().Add(time.Hour),
	})
	g := f.guard(false)
	got := g.OrgProjectSectionStatus(time.Now(), f.listFixture)
	want := []orgcontract.ProjectSectionState{
		{OrgProjectID: "W", Status: orgcontract.ProjectSectionUnknown},
		{OrgProjectID: "X", Status: orgcontract.ProjectSectionApplied},
		{OrgProjectID: "Y", Status: orgcontract.ProjectSectionNotMatched},
		{OrgProjectID: "Z", Status: orgcontract.ProjectSectionNotDelivered},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("status = %+v\nwant %+v", got, want)
	}
	if !orgcontract.ValidProjectSectionStatus(got) {
		t.Fatal("the node's own report must pass the server's check")
	}
	for _, s := range got {
		if strings.ContainsAny(s.OrgProjectID, "/\\") {
			t.Fatalf("a path left the node: %+v", s)
		}
	}

	// Past its offline lifetime: every section is unknown.
	var mf projectmatch.MappingFile
	if err := json.Unmarshal([]byte(f.files[f.layout.MappingPath()]), &mf); err != nil {
		t.Fatal(err)
	}
	mf.AcceptedAt = time.Now().Add(-8 * 24 * time.Hour)
	f.put(f.layout.MappingPath(), mf)
	for _, s := range f.guard(false).OrgProjectSectionStatus(time.Now(), f.listFixture) {
		if s.Status != orgcontract.ProjectSectionUnknown {
			t.Fatalf("expired mapping: %+v", s)
		}
	}

	// A node that holds no v3 delivery reports nothing.
	env, _ := signedEnvelope(t, 4, orgFloor)
	cfg := guardCfgOrg()
	cfg.Rules.ProjectPolicy = ""
	g3, err := New(Options{Config: cfg, Home: "/home/u", ReadFile: fsMap(map[string]string{orgBundlePath: env})})
	if err != nil {
		t.Fatal(err)
	}
	if s := g3.OrgProjectSectionStatus(time.Now(), nil); s != nil {
		t.Fatalf("a v2 node reported %+v", s)
	}
}

// resolveRecord writes a resolve-sourced match record for root.
func (f *orgProjectFixture) sectionResolveRecord(root string, version int64, unknown bool, ids ...string) {
	f.put(f.layout.MatchPath(projectmatch.RootHash(root)), projectmatch.MatchFile{
		ProjectRootHash: projectmatch.RootHash(root), OrgProjectIDs: ids, Epoch: f.epoch, MappingDigest: f.digest,
		MatchedAt: time.Now(), ValidUntil: time.Now().Add(time.Hour),
		Source: projectmatch.SourceResolve, BundleVersion: version, Unknown: unknown,
	})
}

// TestOrgProjectSectionReportReadsWhatTheGuardReads pins SEC-P2B audit
// finding 1: the per-section status reads the match records and envelopes
// the project layer itself reads (lane sec-p2a), one row per case.
func TestOrgProjectSectionReportReadsWhatTheGuardReads(t *testing.T) {
	cases := []struct {
		name  string
		setup func(f *orgProjectFixture)
		want  []orgcontract.ProjectSectionState
	}{
		{"a resolve record applies, through the resolved envelope", func(f *orgProjectFixture) {
			// R is above the mapping cap: not in the mapping, its envelope
			// in the resolved directory.
			f.sectionResolveRecord("/home/u/r", f.version, false, "R")
			f.put(f.layout.ResolvedEnvelopePath("R"), f.envelope("R", projX, f.epoch))
		}, []orgcontract.ProjectSectionState{
			{OrgProjectID: "R", Status: orgcontract.ProjectSectionApplied},
			{OrgProjectID: "X", Status: orgcontract.ProjectSectionNotMatched},
			{OrgProjectID: "Y", Status: orgcontract.ProjectSectionNotMatched},
		}},
		{"a resolve record of another bundle version does not count", func(f *orgProjectFixture) {
			f.sectionResolveRecord("/home/u/y", f.version-1, false, "Y")
		}, []orgcontract.ProjectSectionState{
			{OrgProjectID: "X", Status: orgcontract.ProjectSectionNotMatched},
			{OrgProjectID: "Y", Status: orgcontract.ProjectSectionNotMatched},
		}},
		{"a mapped project's envelope found only in the resolved directory", func(f *orgProjectFixture) {
			delete(f.files, f.layout.EnvelopePath("X"))
			f.put(f.layout.ResolvedEnvelopePath("X"), f.envelope("X", projX, f.epoch))
			f.match("/home/u/x", "X")
		}, []orgcontract.ProjectSectionState{
			{OrgProjectID: "X", Status: orgcontract.ProjectSectionApplied},
			{OrgProjectID: "Y", Status: orgcontract.ProjectSectionNotMatched},
		}},
		{"a current unknown record makes every unmatched section unknown", func(f *orgProjectFixture) {
			f.match("/home/u/x", "X")
			f.sectionResolveRecord("/home/u/none", f.version, true)
		}, []orgcontract.ProjectSectionState{
			{OrgProjectID: "X", Status: orgcontract.ProjectSectionApplied},
			{OrgProjectID: "Y", Status: orgcontract.ProjectSectionUnknown},
		}},
		{"an unknown record of another bundle version does not count", func(f *orgProjectFixture) {
			f.sectionResolveRecord("/home/u/none", f.version-1, true)
		}, []orgcontract.ProjectSectionState{
			{OrgProjectID: "X", Status: orgcontract.ProjectSectionNotMatched},
			{OrgProjectID: "Y", Status: orgcontract.ProjectSectionNotMatched},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newOrgProjectFixture(t, orgFloor, map[string]string{"X": projX, "Y": projY})
			tc.setup(f)
			rep := f.guard(false).OrgProjectSectionReport(time.Now(), f.listFixture)
			if !reflect.DeepEqual(rep.Sections, tc.want) || rep.Truncated {
				t.Fatalf("report = %+v\nwant %+v", rep, tc.want)
			}
		})
	}
}

// TestOrgProjectSectionReportCapsAndValidates pins SEC-P2B audit findings
// 1(b) and 2: the mapping's projects plus the resolved ones are capped at
// the wire bound, an entry the server would refuse is dropped, and either
// cut sets Truncated; the list sent always passes the server's own check, so
// a refused list never drops the reporter to the gen4 rung.
func TestOrgProjectSectionReportCapsAndValidates(t *testing.T) {
	t.Run("above the cap", func(t *testing.T) {
		projects := map[string]string{}
		for i := 0; i < orgcontract.MaxProjectMappingProjects; i++ {
			projects[fmt.Sprintf("p%03d", i)] = projY
		}
		f := newOrgProjectFixture(t, orgFloor, projects)
		// One more, by resolve: 201 candidates. "a" sorts first, so it is
		// kept and the last mapped id is cut.
		f.sectionResolveRecord("/home/u/r", f.version, false, "a")
		f.put(f.layout.ResolvedEnvelopePath("a"), f.envelope("a", projX, f.epoch))
		rep := f.guard(false).OrgProjectSectionReport(time.Now(), f.listFixture)
		if len(rep.Sections) != orgcontract.MaxProjectMappingProjects || !rep.Truncated {
			t.Fatalf("sections %d truncated %v, want %d and true", len(rep.Sections), rep.Truncated, orgcontract.MaxProjectMappingProjects)
		}
		if rep.Sections[0] != (orgcontract.ProjectSectionState{OrgProjectID: "a", Status: orgcontract.ProjectSectionApplied}) {
			t.Fatalf("first = %+v", rep.Sections[0])
		}
		if !orgcontract.ValidProjectSectionStatus(rep.Sections) {
			t.Fatal("the capped list must pass the server's check")
		}
	})
	t.Run("an id the server would refuse", func(t *testing.T) {
		f := newOrgProjectFixture(t, orgFloor, map[string]string{"X": projX, "bad id": projY})
		rep := f.guard(false).OrgProjectSectionReport(time.Now(), f.listFixture)
		want := []orgcontract.ProjectSectionState{{OrgProjectID: "X", Status: orgcontract.ProjectSectionNotMatched}}
		if !reflect.DeepEqual(rep.Sections, want) || !rep.Truncated {
			t.Fatalf("report = %+v, want %+v truncated", rep, want)
		}
	})
	t.Run("nothing cut", func(t *testing.T) {
		f := newOrgProjectFixture(t, orgFloor, map[string]string{"X": projX})
		if rep := f.guard(false).OrgProjectSectionReport(time.Now(), f.listFixture); rep.Truncated || len(rep.Sections) != 1 {
			t.Fatalf("report = %+v", rep)
		}
	})
}

// TestLazyBaseThatDropsTheOrgLayerIsNotReported pins the P-058 follow-up
// from the SEC-P2A merge: when the lazily built base engine's ladder drops
// the org layer, no status surface reports that layer (or its project
// sections) as loaded: not PolicyStates (what `observer guard status` prints
// and the policy-state reporter reads), not the project floor line, not the
// project cache issues and not the per-section status.
func TestLazyBaseThatDropsTheOrgLayerIsNotReported(t *testing.T) {
	f := newOrgProjectFixture(t, orgFloor, map[string]string{"X": projX})
	f.match("/home/u/x", "X")
	g := f.guard(false)
	cur := g.set.Load()
	if cur.baseBuild == nil {
		t.Fatal("a v3 org layer seals a lazy snapshot")
	}
	if !hasLayer(g.PolicyStates(), layerOrg) || len(g.OrgProjectSectionStatus(time.Now(), f.listFixture)) != 1 {
		t.Fatal("before: the org layer and its section are reported")
	}
	if _, ok := g.OrgProjectUnknown(); !ok {
		t.Fatal("before: the project floor is reported")
	}
	// The same snapshot, whose base build drops the org layer.
	base := cur.base()
	g.set.Store(newLazyEngineSet(cur.mode, func() (*policy.Engine, []string) { return base, []string{layerOrg} },
		cur.orgLayer, cur.userLayer, cur.states, cur.ruleCategories, cur.budgetBinding))
	if hasLayer(g.PolicyStates(), layerOrg) {
		t.Fatalf("a dropped org layer is reported loaded: %+v", g.PolicyStates())
	}
	if rep := g.OrgProjectSectionReport(time.Now(), f.listFixture); rep.Sections != nil || rep.Truncated {
		t.Fatalf("project sections reported under a dropped org layer: %+v", rep)
	}
	if _, ok := g.OrgProjectUnknown(); ok {
		t.Fatal("the project floor is reported under a dropped org layer")
	}
	if issues := g.OrgProjectCacheIssues(); issues != nil {
		t.Fatalf("project cache issues under a dropped org layer: %v", issues)
	}
}

func hasLayer(states []PolicyState, layer string) bool {
	for _, s := range states {
		if s.Layer == layer {
			return true
		}
	}
	return false
}
