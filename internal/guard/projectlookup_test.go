package guard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
)

// Lane sec-p2a merge fixes (audit findings 1, 2, 3 and 7): the hook's derived
// project root, the floor only where a project bundle could apply, the
// resolve record read under the identity root, and the cache rebuild.

// gitRepo makes a directory that is a git working tree (a .git directory,
// origin's url when remote is set), for the identity reads that touch the
// real disk (projectmatch.SignalsFor, git.FindRoot). No git process runs.
func gitRepo(t *testing.T, remote string) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if remote != "" {
		cfg := "[remote \"origin\"]\n\turl = " + remote + "\n"
		if err := os.WriteFile(filepath.Join(dir, ".git", "config"), []byte(cfg), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// makeWorktree adds a linked worktree of main in git's own layout and returns
// its top level.
func makeWorktree(t *testing.T, main string) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	wt := filepath.Join(base, "wt")
	gd := filepath.Join(main, ".git", "worktrees", "wt")
	for _, d := range []string{gd, wt} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for path, body := range map[string]string{
		filepath.Join(gd, "commondir"): "../..\n",
		filepath.Join(gd, "gitdir"):    filepath.Join(wt, ".git") + "\n",
		filepath.Join(wt, ".git"):      "gitdir: " + gd + "\n",
	} {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return wt
}

// truncate marks the fixture's mapping as above the cap (re-signed, with the
// composed bundle's binding re-signed to its new digest).
func (f *orgProjectFixture) truncate() {
	f.t.Helper()
	var mf projectmatch.MappingFile
	if err := json.Unmarshal([]byte(f.files[f.layout.MappingPath()]), &mf); err != nil {
		f.t.Fatal(err)
	}
	mf.Mapping.Truncated = true
	mf.Mapping = orgcontract.SignProjectMapping(f.priv, mf.Mapping)
	f.digest = orgcontract.ProjectMappingDigest(mf.Mapping)
	f.put(f.layout.MappingPath(), mf)
	var b orgcontract.PolicyBundle
	if err := json.Unmarshal([]byte(f.files[orgBundlePath]), &b); err != nil {
		f.t.Fatal(err)
	}
	b.ProjectBinding.MappingDigest = f.digest
	b.Signature = ""
	b.Signature = orgcontract.SignPolicyBundleEnvelope(f.priv, b)
	f.put(orgBundlePath, b)
}

// resolveRecord writes the matcher's resolve record for root (keyed by the
// root as given: the matcher passes the identity root).
func (f *orgProjectFixture) resolveRecord(root string, ids ...string) {
	f.put(f.layout.MatchPath(projectmatch.RootHash(root)), projectmatch.MatchFile{
		ProjectRootHash: projectmatch.RootHash(root), OrgProjectIDs: ids, Epoch: f.epoch, MappingDigest: f.digest,
		Source: projectmatch.SourceResolve, BundleVersion: f.version, MatchedAt: time.Now(), ValidUntil: time.Now().Add(time.Hour),
	})
}

// TestHookLookupRootReachesTheProjectLayer is audit finding 1 (guard half): a
// pre-tool event with no ProjectRoot (Claude Code's PreToolUse carries only
// cwd) but the boundary's derived ProjectLookupRoot gets its matched
// project's sections and, in an unknown root, the floor; the rules and the
// recorded row still see the empty ProjectRoot.
func TestHookLookupRootReachesTheProjectLayer(t *testing.T) {
	root := gitRepo(t, "https://github.com/acme/x.git")
	hookEv := func(cmd string) policy.Event {
		ev := floorEvent("", func(e *policy.Event) { e.Target = cmd })
		ev.ProjectLookupRoot = root
		return ev
	}
	f := newOrgProjectFixture(t, orgFloor+askFloor, map[string]string{"X": projX})
	f.match(root, "X")
	av, _ := f.floorGuard(boolp(false)).EvaluateHook(hookEv("curl https://billing.internal/x"))
	if av.Verdict.RuleID != "PRJ-X1" || av.Verdict.Decision != policy.DecisionDeny {
		t.Fatalf("matched root through the lookup root: %s/%s, want PRJ-X1 deny", av.Verdict.RuleID, av.Verdict.Decision)
	}
	if av.Input.ProjectRoot != "" {
		t.Fatalf("the recorded row's ProjectRoot = %q, want the event's own (empty)", av.Input.ProjectRoot)
	}
	// Without the lookup root the same event reaches only the base engine.
	plain := hookEv("curl https://billing.internal/x")
	plain.ProjectLookupRoot = ""
	if av, _ := f.floorGuard(boolp(false)).EvaluateHook(plain); av.Verdict.RuleID == "PRJ-X1" {
		t.Fatal("an event with no root at all loaded a project layer")
	}

	f2 := newOrgProjectFixture(t, orgFloor+askFloor, map[string]string{"X": projX})
	f2.expireMapping(root)
	av, _ = f2.floorGuard(boolp(false)).EvaluateHook(hookEv("make test"))
	if av.Verdict.RuleID != ProjectUnknownRuleID || av.Verdict.Decision != policy.DecisionAsk {
		t.Fatalf("unknown root through the lookup root: %s/%s, want the floor's ask", av.Verdict.RuleID, av.Verdict.Decision)
	}
}

// TestProjectUnknownFloorOnlyWhereAProjectBundleReaches is audit finding 2: a
// member no project bundle reaches (the last signed mapping lists none and is
// complete), offline 8 days, is not asked in a non-git directory or in an
// unmatched repository; a member some project reaches still gets the floor
// in an unmatched repository, but never in a non-git directory.
func TestProjectUnknownFloorOnlyWhereAProjectBundleReaches(t *testing.T) {
	repo := gitRepo(t, "https://github.com/acme/unlisted.git")
	plain, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name     string
		projects map[string]string
		root     string
		floor    bool
	}{
		{"no project reaches, non-git directory", map[string]string{}, plain, false},
		{"no project reaches, unmatched repository", map[string]string{}, repo, false},
		{"a project reaches, unmatched repository", map[string]string{"X": projX}, repo, true},
		{"a project reaches, non-git directory", map[string]string{"X": projX}, plain, false},
	}
	for _, row := range rows {
		f := newOrgProjectFixture(t, orgFloor+askFloor, row.projects)
		f.expireMapping(row.root)
		for _, managed := range []bool{false, true} {
			av, _ := f.floorGuard(boolp(managed)).EvaluateHook(floorEvent(row.root, nil))
			if got := av.Verdict.RuleID == ProjectUnknownRuleID; got != row.floor {
				t.Errorf("%s (managed=%v): %s/%s, floor %v want %v", row.name, managed, av.Verdict.RuleID, av.Verdict.Decision, got, row.floor)
			}
		}
	}
}

// TestResolveRecordIsReadUnderTheIdentityRoot is audit finding 3 (P-041):
// above the cap the matcher keys a resolve record by the identity root (the
// main repository for a linked worktree, the repository root for a
// subdirectory); the guard reads it there, so the resolved project's
// sections apply and the floor stays quiet.
func TestResolveRecordIsReadUnderTheIdentityRoot(t *testing.T) {
	main := gitRepo(t, "https://github.com/acme/widget.git")
	sub := filepath.Join(main, "pkg", "api")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	wt := makeWorktree(t, main)
	for _, dir := range []struct{ name, path string }{{"main repository", main}, {"subdirectory", sub}, {"linked worktree", wt}} {
		f := newOrgProjectFixture(t, orgFloor+askFloor, map[string]string{"A": projY})
		f.truncate()
		f.resolveRecord(main, "Z")
		f.put(f.layout.ResolvedEnvelopePath("Z"), f.envelope("Z", projX, f.epoch))
		g := f.floorGuard(boolp(true))
		av, _ := g.EvaluateHook(floorEvent(dir.path, func(e *policy.Event) { e.Target = "curl https://billing.internal/x" }))
		if av.Verdict.RuleID != "PRJ-X1" {
			t.Errorf("%s: %s/%s, want the resolved project's PRJ-X1; issues %v", dir.name, av.Verdict.RuleID, av.Verdict.Decision, g.LoadIssues())
		}
		if av, _ := g.EvaluateHook(floorEvent(dir.path, nil)); av.Verdict.RuleID == ProjectUnknownRuleID {
			t.Errorf("%s: the floor fired despite a current resolve answer", dir.name)
		}
	}
}

// TestProjectRebuildReplacesItsStates is audit finding 7: a root rebuilt
// after its match changed reports the new layers and drops the old ones, and
// a layer the dropped engine already reported is not fired again.
func TestProjectRebuildReplacesItsStates(t *testing.T) {
	saved := projectRecheckEvery
	projectRecheckEvery = 0
	t.Cleanup(func() { projectRecheckEvery = saved })
	f := newOrgProjectFixture(t, orgFloor, map[string]string{"X": projX, "Y": projY})
	f.match("/home/u/x", "X")
	cfg := guardCfgOrg()
	cfg.Rules.ProjectPolicy = ""
	var fired []string
	g, err := New(Options{Config: cfg, Home: "/home/u", ReadFile: fsMap(f.files), OnPolicyState: func(ps PolicyState) {
		if ps.Layer == layerOrgProject {
			fired = append(fired, ps.Path)
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	projectStates := func() []string {
		var out []string
		for _, ps := range g.PolicyStates() {
			if ps.Layer == layerOrgProject {
				out = append(out, ps.Path)
			}
		}
		return out
	}
	xPath, yPath := f.layout.EnvelopePath("X"), f.layout.EnvelopePath("Y")
	g.Evaluate(shell("/home/u/x", "true"))
	f.match("/home/u/x", "Y")
	g.Evaluate(shell("/home/u/x", "true"))
	if got := projectStates(); len(got) != 1 || got[0] != yPath {
		t.Fatalf("after X -> Y the states are %v, want only %s", got, yPath)
	}
	f.match("/home/u/x", "X", "Y")
	g.Evaluate(shell("/home/u/x", "true"))
	if got := projectStates(); len(got) != 2 {
		t.Fatalf("after Y -> X,Y the states are %v, want both", got)
	}
	want := []string{xPath, yPath, xPath}
	if len(fired) != len(want) {
		t.Fatalf("fired %v, want %v (Y not fired again when it stayed)", fired, want)
	}
	for i := range want {
		if fired[i] != want[i] {
			t.Fatalf("fired %v, want %v", fired, want)
		}
	}
}

// TestProjectRecheckReadsOutsideTheLock is audit finding 7: the periodic
// re-check of a cached root reads its record, mapping and envelopes without
// holding the snapshot's project cache lock.
func TestProjectRecheckReadsOutsideTheLock(t *testing.T) {
	saved := projectRecheckEvery
	projectRecheckEvery = 0
	t.Cleanup(func() { projectRecheckEvery = saved })
	f := newOrgProjectFixture(t, orgFloor, map[string]string{"X": projX})
	f.match("/home/u/x", "X")
	cfg := guardCfgOrg()
	cfg.Rules.ProjectPolicy = ""
	var (
		gp            atomic.Pointer[Guard]
		watch, locked atomic.Bool
		reads         atomic.Int64
	)
	read := fsMap(f.files)
	g, err := New(Options{Config: cfg, Home: "/home/u", ReadFile: func(p string) ([]byte, error) {
		if watch.Load() {
			reads.Add(1)
			es := gp.Load().set.Load()
			if es.pmu.TryLock() {
				es.pmu.Unlock()
			} else {
				locked.Store(true)
			}
		}
		return read(p)
	}})
	if err != nil {
		t.Fatal(err)
	}
	gp.Store(g)
	g.Evaluate(shell("/home/u/x", "true"))
	watch.Store(true)
	g.Evaluate(shell("/home/u/x", "true"))
	if reads.Load() == 0 {
		t.Fatal("the re-check read nothing")
	}
	if locked.Load() {
		t.Fatal("the re-check read files while holding the project cache lock")
	}
}
