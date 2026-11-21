package workspace

import (
	"strings"
	"testing"
)

func TestDecideDiffBase(t *testing.T) {
	sha := strings.Repeat("c", 40)
	clean := DiffBaseFacts{Commit: sha, StatusKnown: true, StatusClean: true}
	cases := []struct {
		name  string
		edit  func(f *DiffBaseFacts)
		exact bool
		want  string
	}{
		{"a clean folder at a commit opens as a branch", func(*DiffBaseFacts) {}, true, ""},
		{"a folder that is not a repository (SBXD-8)", func(f *DiffBaseFacts) {
			*f = DiffBaseFacts{NoRepository: true, AgentCommits: 0, Truncated: true}
		}, false, "not a git repository, so there is no branch to open"},
		{"a cut diff", func(f *DiffBaseFacts) { f.Truncated = true }, false, "cut at its size limit"},
		{"the agent committed in the box", func(f *DiffBaseFacts) { f.AgentCommits = 2 }, false, "2 commit(s) of its own"},
		{"the agent's commits are unknown", func(f *DiffBaseFacts) { f.AgentCommits = -1 }, false, "could not tell whether the agent made commits"},
		// The diff against the box's baseline (the smaller item of the
		// sandbox decisions): the agent's commits are in it, so they no
		// longer refuse the branch; a cut diff or an unknown base still do.
		{"the agent committed, and the diff starts at the baseline", func(f *DiffBaseFacts) { f.AgentCommits, f.IncludesAgentCommits = 3, true }, true, ""},
		{"uncounted commits, and the diff starts at the baseline", func(f *DiffBaseFacts) { f.AgentCommits, f.IncludesAgentCommits = -1, true }, true, ""},
		{"a cut diff that starts at the baseline", func(f *DiffBaseFacts) { f.AgentCommits, f.IncludesAgentCommits, f.Truncated = 3, true, true }, false, "cut at its size limit"},
		{"a baseline diff from a folder with no commit", func(f *DiffBaseFacts) { f.AgentCommits, f.IncludesAgentCommits, f.Commit = 1, true, "" }, false, "no commit Observer could read"},
		{"a baseline diff from a dirty folder", func(f *DiffBaseFacts) { f.AgentCommits, f.IncludesAgentCommits, f.StatusClean = 1, true, false }, false, "had uncommitted changes"},
		{"a box-side clone with no recorded commit", func(f *DiffBaseFacts) { *f = DiffBaseFacts{RemoteClone: true} }, false, "commit it cloned was not recorded"},
		{"a box-side clone at a recorded commit", func(f *DiffBaseFacts) { *f = DiffBaseFacts{RemoteClone: true, Commit: sha} }, true, ""},
		{"no commit when the files were sent", func(f *DiffBaseFacts) { f.Commit = "" }, false, "no commit Observer could read"},
		{"status unread", func(f *DiffBaseFacts) { f.StatusKnown = false }, false, "could not tell whether the folder had uncommitted changes"},
		{"uncommitted changes", func(f *DiffBaseFacts) { f.StatusClean = false }, false, "had uncommitted changes"},
	}
	for _, c := range cases {
		f := clean
		c.edit(&f)
		v := DecideDiffBase(f)
		if v.Exact != c.exact || (c.want != "" && !strings.Contains(v.Reason, c.want)) || (c.exact && v.Reason != "") {
			t.Errorf("%s: got %+v", c.name, v)
		}
	}
	// One test case per row: the table has exactly the rows above.
	if len(diffBaseRules) != 10 {
		t.Fatalf("diffBaseRules has %d rows; give the new row a case", len(diffBaseRules))
	}
}

func testDiffBranchReq() DiffBranchRequest {
	return DiffBranchRequest{Repo: "/home/dev/src/app", DiffPath: "/tmp/observer-diff-1/run.diff", TempDir: "/tmp/observer-diff-1", RunID: "RUN1", Base: strings.Repeat("a", 40)}
}

func TestPlanDiffBranchSteps(t *testing.T) {
	p, err := PlanDiffBranch(testDiffBranchReq())
	if err != nil {
		t.Fatal(err)
	}
	if p.Ref != "refs/heads/observer-sandbox/RUN1/changes" || DiffBranchName(p.Ref) != "observer-sandbox/RUN1/changes" {
		t.Fatalf("ref %q", p.Ref)
	}
	tree := strings.Repeat("b", 40)
	steps := map[string]GitStep{
		"verify": p.VerifyBase(), "exists": p.RefExists(), "paths": p.DiffPaths(), "ancestor": p.FakeAncestor(),
		"list-ancestor": p.ListAncestor(), "base": p.ListBase(), "seed": p.SeedIndex(), "apply": p.Apply(),
		"write": p.WriteTree(), "changed": p.ChangedEntries(tree), "tree": p.ListTree(tree), "blob": p.ReadBlob(tree),
		"commit": p.CommitTree(tree), "ref": p.CreateRef(tree), "readback": p.VerifyRef(),
	}
	for name, st := range steps {
		got := strings.Join(st.Argv, " ")
		// Every step runs in the person's repository, hooks and fsmonitor off.
		if !strings.HasPrefix(got, "git -C /home/dev/src/app -c core.hooksPath=") || !strings.Contains(got, "core.fsmonitor=false") {
			t.Errorf("%s: %s", name, got)
		}
		for _, kv := range st.Env {
			// The only environment a step adds: a temporary index under the
			// temporary folder, and the commit identity.
			if strings.HasPrefix(kv, "GIT_INDEX_FILE=") && !strings.HasPrefix(kv, "GIT_INDEX_FILE=/tmp/observer-diff-1/") {
				t.Errorf("%s: the index is not a temporary one: %s", name, kv)
			}
			if !strings.HasPrefix(kv, "GIT_INDEX_FILE=") && !strings.HasPrefix(kv, "GIT_AUTHOR_") && !strings.HasPrefix(kv, "GIT_COMMITTER_") {
				t.Errorf("%s: an unexpected environment entry %s", name, kv)
			}
		}
	}
	// Anything that could reach an index reaches only the temporary one.
	for _, name := range []string{"paths", "ancestor", "seed", "apply", "write", "list-ancestor"} {
		if len(steps[name].Env) == 0 {
			t.Errorf("%s runs on the repository's own index", name)
		}
	}
	for _, name := range []string{"paths", "ancestor", "apply"} {
		if !strings.Contains(strings.Join(steps[name].Argv, " "), "apply --cached") {
			t.Errorf("%s may reach the working tree: %q", name, steps[name].Argv)
		}
		if strings.Contains(strings.Join(steps[name].Argv, " "), "--3way") {
			t.Errorf("%s merges three ways", name)
		}
	}
	ref := p.CreateRef(tree).Argv
	if ref[len(ref)-1] != "" || ref[len(ref)-2] != tree || ref[len(ref)-3] != p.Ref {
		t.Fatalf("the branch is not written create-only (empty old value): %q", ref)
	}
	if c := strings.Join(p.CommitTree(tree).Argv, " "); !strings.Contains(c, "-p "+strings.Repeat("a", 40)) {
		t.Fatalf("the commit's parent is not the base: %s", c)
	}
}

func TestPlanDiffBranchRefuses(t *testing.T) {
	for name, edit := range map[string]func(r *DiffBranchRequest){
		"relative repository": func(r *DiffBranchRequest) { r.Repo = "app" },
		"bad run id":          func(r *DiffBranchRequest) { r.RunID = "../x" },
		"run id with a space": func(r *DiffBranchRequest) { r.RunID = "a b" },
		"base not a commit":   func(r *DiffBranchRequest) { r.Base = "HEAD" },
		"temp inside the repo": func(r *DiffBranchRequest) {
			r.TempDir, r.DiffPath = "/home/dev/src/app/.t", "/home/dev/src/app/.t/run.diff"
		},
		"diff not the temp copy":    func(r *DiffBranchRequest) { r.DiffPath = "/home/dev/.observer/sandbox-hosted/returns/RUN1.diff" },
		"repository inside temp":    func(r *DiffBranchRequest) { r.Repo = "/tmp/observer-diff-1/app" },
		"a dot-dot temporary path":  func(r *DiffBranchRequest) { r.TempDir = "/tmp/../tmp/x" },
		"a control character in it": func(r *DiffBranchRequest) { r.Repo = "/home/dev/src/a\x01pp" },
	} {
		r := testDiffBranchReq()
		edit(&r)
		if _, err := PlanDiffBranch(r); err == nil {
			t.Errorf("%s: planned", name)
		}
	}
}

func TestCheckDiffPaths(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
		bad  string
	}{
		{"one file", "1\t0\ta.txt\x00", []string{"a.txt"}, ""},
		{"a binary and a rename", "-\t-\tbin.dat\x000\t0\t\x00old.txt\x00new.txt\x00", []string{"bin.dat", "old.txt", "new.txt"}, ""},
		{"absolute", "1\t0\t/etc/passwd\x00", nil, "absolute"},
		{"dot-dot", "1\t0\t../x\x00", nil, "leaves the repository"},
		{"a .git component", "1\t0\tsub/.git/config\x00", nil, ".git directory"},
		{"a .git look-alike", "1\t0\t.GIT. \x00", nil, ".git directory"},
		{"a control character", "1\t0\ta\x01b\x00", nil, "control character"},
		{"a rename to .git", "0\t0\t\x00ok.txt\x00.git/hooks/pre-commit\x00", nil, ".git directory"},
		{"no file", "", nil, "changes no file"},
		{"not numstat", "garbage\x00", nil, "not <added>"},
		{"a cut rename", "0\t0\t\x00only-old\x00", nil, "inside a rename"},
	}
	for _, c := range cases {
		got, err := CheckDiffPaths([]byte(c.in))
		if c.bad != "" {
			if err == nil || !strings.Contains(err.Error(), c.bad) {
				t.Errorf("%s: err %v", c.name, err)
			}
			continue
		}
		if err != nil || strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s: %q %v", c.name, got, err)
		}
	}
}

func TestCheckAncestorMatchesBase(t *testing.T) {
	a, b := strings.Repeat("a", 40), strings.Repeat("b", 40)
	base := []TreeEntry{{Mode: "100644", Type: "blob", Object: a, Path: "x.txt"}, {Mode: "100755", Type: "blob", Object: b, Path: "run.sh"}}
	cases := []struct {
		name string
		anc  []IndexEntry
		bad  string
	}{
		{"the same files", []IndexEntry{{Mode: "100644", Object: a, Path: "x.txt"}, {Mode: "100755", Object: b, Path: "run.sh"}}, ""},
		{"nothing to change", nil, ""},
		{"a file the base lacks", []IndexEntry{{Mode: "100644", Object: a, Path: "y.txt"}}, "does not have"},
		{"another version", []IndexEntry{{Mode: "100644", Object: b, Path: "x.txt"}}, "not the one in commit"},
		{"another mode", []IndexEntry{{Mode: "100755", Object: a, Path: "x.txt"}}, "file mode"},
	}
	for _, c := range cases {
		err := CheckAncestorMatchesBase(c.anc, base, strings.Repeat("d", 40))
		if (c.bad == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.bad)) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestParseRawDiffAndCheckChangedEntries(t *testing.T) {
	z := strings.Repeat("0", 40)
	o := strings.Repeat("1", 40)
	raw := ":100644 100644 " + o + " " + o + " M\x00a.txt\x00:000000 120000 " + z + " " + o + " A\x00link\x00"
	es, err := ParseRawDiff([]byte(raw))
	if err != nil || len(es) != 2 || es[1].Path != "link" || es[1].NewMode != "120000" {
		t.Fatalf("%+v %v", es, err)
	}
	links, err := CheckChangedEntries(es)
	if err != nil || len(links) != 1 || links[0].Path != "link" {
		t.Fatalf("%+v %v", links, err)
	}
	for name, in := range map[string]string{
		"a gitlink":      ":000000 160000 " + z + " " + o + " A\x00sub\x00",
		"a .git path":    ":000000 100644 " + z + " " + o + " A\x00.git/config\x00",
		"a bad link oid": ":000000 120000 " + z + " nope A\x00l\x00",
	} {
		es, err := ParseRawDiff([]byte(in))
		if err == nil {
			_, err = CheckChangedEntries(es)
		}
		if err == nil {
			t.Errorf("%s: passed", name)
		}
	}
	if _, err := ParseRawDiff([]byte("not raw\x00")); err == nil {
		t.Fatal("a line that is not raw passed")
	}
}

func TestCheckSymlinkChainsFrom(t *testing.T) {
	targets := map[string]string{"d/up": "..", "esc": "d/up/../x", "mine": "/usr/share/dict"}
	// A changed link that climbs out through the person's own link is
	// refused; the person's own absolute link is not judged by itself.
	if err := CheckSymlinkChainsFrom([]string{"esc"}, targets); err == nil {
		t.Fatal("a chain out of the tree passed")
	}
	if err := CheckSymlinkChainsFrom([]string{"d/up"}, map[string]string{"d/up": "..", "mine": "/usr/share/dict"}); err != nil {
		t.Fatalf("a link to the top of the tree was refused: %v", err)
	}
	if err := CheckSymlinkChainsFrom([]string{"via"}, map[string]string{"via": "mine/x", "mine": "/usr/share"}); err == nil {
		t.Fatal("a chain through an absolute link passed")
	}
}

func TestParseIndexAndTreeEntries(t *testing.T) {
	sha := strings.Repeat("e", 40)
	es, err := ParseIndexEntries([]byte("100644 " + sha + " 0\tdir/a b.txt\x00"))
	if err != nil || len(es) != 1 || es[0].Path != "dir/a b.txt" || es[0].Object != sha {
		t.Fatalf("%+v %v", es, err)
	}
	if _, err := ParseIndexEntries([]byte("100644 nope 0\tx\x00")); err == nil {
		t.Fatal("a bad object passed")
	}
	ts, err := ParseTreeEntries([]byte("100644 blob " + sha + "\tx\x00"))
	if err != nil || len(ts) != 1 || ts[0].Type != "blob" {
		t.Fatalf("%+v %v", ts, err)
	}
}

func TestDiffApplyCommand(t *testing.T) {
	if got := DiffApplyCommand("/home/dev/.observer/r/RUN1.diff"); got != "git apply --index /home/dev/.observer/r/RUN1.diff" {
		t.Fatal(got)
	}
	if got := DiffApplyCommand("/home/my dev/it's.diff"); got != `git apply --index '/home/my dev/it'\''s.diff'` {
		t.Fatal(got)
	}
}
