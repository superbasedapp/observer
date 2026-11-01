package workspace

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestWorktreeBranch(t *testing.T) {
	cases := []struct {
		id, label, want string
		ok              bool
	}{
		{"run1", "", "observer-sandbox/run1/work", true},
		{"run1", "fix-login", "observer-sandbox/run1/fix-login", true},
		{"run1", "a/b", "", false},
		{"run1", "-x", "", false},
		{"run1", "x.lock", "", false},
		{"run1", ".hidden", "", false},
		{"run1", "a..b", "", false},
		{"run1", "has space", "", false},
		{"", "work", "", false},
		{"../x", "work", "", false},
		// git check-ref-format's one-component rules (SHR-FOLLOWUPS, the
		// dashboard's worktree branch field).
		{"run1", "fix.v2", "observer-sandbox/run1/fix.v2", true},
		{"run1", "feature_x@2", "observer-sandbox/run1/feature_x@2", true},
		{"run1", "a\\b", "", false},
		{"run1", "ends.", "", false},
		{"run1", "a@{1}", "", false},
		{"run1", "@", "", false},
		{"run1", "a~1", "", false},
		{"run1", "a^", "", false},
		{"run1", "a:b", "", false},
		{"run1", "a?", "", false},
		{"run1", "a*", "", false},
		{"run1", "a[0]", "", false},
		{"run1", "tab\there", "", false},
		{"run1", strings.Repeat("x", MaxRefComponentLen+1), "", false},
		{"run1", strings.Repeat("x", MaxRefComponentLen), "observer-sandbox/run1/" + strings.Repeat("x", MaxRefComponentLen), true},
	}
	for _, c := range cases {
		got, err := WorktreeBranch(c.id, c.label)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("WorktreeBranch(%q, %q) = %q, %v; want %q ok=%v", c.id, c.label, got, err, c.want, c.ok)
		}
	}
	if got := WorktreeRunRefDir("observer-sandbox/run1/work"); got != filepath.Join("refs", "heads", "observer-sandbox", "run1") {
		t.Fatalf("WorktreeRunRefDir = %q", got)
	}
}

func worktreeLayout() WorktreeLayout {
	common := filepath.FromSlash("/home/u/repo/.git")
	return WorktreeLayout{
		WorkspaceDir: filepath.FromSlash("/home/u/.observer/workspaces/run1/repo"),
		CommonDir:    common,
		AdminDir:     filepath.Join(common, "worktrees", "repo"),
		Branch:       "observer-sandbox/run1/work",
		OtherAdmins:  []string{filepath.Join(common, "worktrees", "repo"), filepath.Join(common, "worktrees", "feature"), filepath.FromSlash("/elsewhere/worktrees/x")},
		RefDirExists: true, LogDirExists: true,
	}
}

// TestPlanWorktreeBoxBinds (milestone 1 and 3): the whole common dir is
// read-only and only what a commit on the run's branch writes is
// read-write: the object store, the worktree's own git dir, and the run's
// ref and reflog directories. No other ref, no packed-refs, no main
// checkout HEAD or index is under a read-write bind.
func TestPlanWorktreeBoxBinds(t *testing.T) {
	l := worktreeLayout()
	box, err := PlanWorktreeBox(l)
	if err != nil {
		t.Fatal(err)
	}
	c := l.CommonDir
	if !reflect.DeepEqual(box.ReadOnly, []string{c}) {
		t.Fatalf("ReadOnly = %v", box.ReadOnly)
	}
	wantRW := []string{
		filepath.Join(c, "objects"),
		l.AdminDir,
		filepath.Join(c, "refs", "heads", "observer-sandbox", "run1"),
		filepath.Join(c, "logs", "refs", "heads", "observer-sandbox", "run1"),
	}
	if !reflect.DeepEqual(box.ReadWrite, wantRW) {
		t.Fatalf("ReadWrite = %v, want %v", box.ReadWrite, wantRW)
	}
	// Every path a box must never move stays outside the read-write binds.
	for _, rel := range []string{
		"HEAD", "index", "packed-refs", "config", "hooks/pre-commit",
		"refs/heads/main", "refs/heads/observer-sandbox/other/work", "refs/tags/v1", "refs/remotes/origin/main",
		"refs/stash", "logs/refs/heads/main", "worktrees/feature/HEAD", "FETCH_HEAD", "info/exclude",
	} {
		p := filepath.Join(c, filepath.FromSlash(rel))
		for _, rw := range box.ReadWrite {
			if within(p, rw) {
				t.Errorf("%s is under the read-write bind %s", rel, rw)
			}
		}
	}
	// The protected rows: the common dir's executed state, the files git
	// follows inside the read-write binds, the other worktrees' git dirs.
	got := map[string]bool{}
	for _, r := range box.Protect {
		got[r.Path] = r.Dir
	}
	for p, dir := range map[string]bool{
		filepath.Join(c, "hooks"):                         true,
		filepath.Join(c, "config"):                        false,
		filepath.Join(c, "info"):                          true,
		filepath.Join(c, "config.worktree"):               false,
		filepath.Join(c, "objects", "info", "alternates"): false,
		filepath.Join(l.AdminDir, "commondir"):            false,
		filepath.Join(l.AdminDir, "gitdir"):               false,
		filepath.Join(l.AdminDir, "config.worktree"):      false,
		filepath.Join(l.WorkspaceDir, ".git"):             false,
		filepath.Join(c, "worktrees", "feature"):          true,
	} {
		if d, ok := got[p]; !ok || d != dir {
			t.Errorf("protect row %s: present %v dir %v, want dir %v", p, ok, d, dir)
		}
	}
	if _, ok := got[l.AdminDir]; ok {
		t.Error("the run's own worktree git dir is a read-only row")
	}
	if _, ok := got[filepath.FromSlash("/elsewhere/worktrees/x")]; ok {
		t.Error("a git dir outside the common dir's worktrees is a row")
	}

	l.LogDirExists = false
	box, err = PlanWorktreeBox(l)
	if err != nil || len(box.ReadWrite) != 3 {
		t.Fatalf("no reflog dir: %v %v", box.ReadWrite, err)
	}
}

func TestPlanWorktreeBoxRefusals(t *testing.T) {
	for name, mut := range map[string]func(*WorktreeLayout){
		"admin outside worktrees": func(l *WorktreeLayout) { l.AdminDir = filepath.Join(l.CommonDir, "repo") },
		"relative common":         func(l *WorktreeLayout) { l.CommonDir = "repo/.git" },
		"workspace in common":     func(l *WorktreeLayout) { l.WorkspaceDir = filepath.Join(l.CommonDir, "x") },
		"common in workspace":     func(l *WorktreeLayout) { l.WorkspaceDir = filepath.Dir(l.CommonDir) },
		"foreign branch":          func(l *WorktreeLayout) { l.Branch = "main" },
		"deeper branch":           func(l *WorktreeLayout) { l.Branch = "observer-sandbox/run1/a/b" },
		"no ref dir (reftable)":   func(l *WorktreeLayout) { l.RefDirExists = false },
	} {
		l := worktreeLayout()
		mut(&l)
		if _, err := PlanWorktreeBox(l); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPlanWorktreeBoxCapsOtherWorktrees(t *testing.T) {
	l := worktreeLayout()
	l.OtherAdmins = nil
	for i := 0; i < WorktreeProtectCap+10; i++ {
		l.OtherAdmins = append(l.OtherAdmins, filepath.Join(l.CommonDir, "worktrees", "w"+strings.Repeat("x", i+1)))
	}
	box, err := PlanWorktreeBox(l)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range box.Protect {
		if filepath.Dir(r.Path) == filepath.Join(l.CommonDir, "worktrees") {
			n++
		}
	}
	if n != WorktreeProtectCap {
		t.Fatalf("other worktree rows = %d, want the cap %d (the rest stay read-only through the common dir's bind)", n, WorktreeProtectCap)
	}
}

// TestDecideWorktreeEnd is the end-of-run table, one case per row: a
// worktree is removed only when it is clean, on the run's branch and not
// locked, and a branch is deleted only while it still points at the base.
func TestDecideWorktreeEnd(t *testing.T) {
	const base, moved = "1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222"
	live := WorktreeEndFacts{Registered: true, DirExists: true, OnBranch: true, BranchTip: base, Base: base}
	with := func(mut func(*WorktreeEndFacts)) WorktreeEndFacts { f := live; mut(&f); return f }
	cases := []struct {
		name   string
		f      WorktreeEndFacts
		action WorktreeEndAction
		del    bool
	}{
		{"gone, unmoved branch", with(func(f *WorktreeEndFacts) { f.DirExists = false }), WorktreeEndPruneOnly, true},
		{"gone, branch with commits", with(func(f *WorktreeEndFacts) { f.DirExists = false; f.BranchTip = moved }), WorktreeEndPruneOnly, false},
		{"gone, branch already deleted", with(func(f *WorktreeEndFacts) { f.DirExists = false; f.BranchTip = "" }), WorktreeEndPruneOnly, false},
		{"unregistered", with(func(f *WorktreeEndFacts) { f.Registered = false }), WorktreeEndKeep, false},
		{"locked", with(func(f *WorktreeEndFacts) { f.Locked = true }), WorktreeEndKeep, false},
		{"off branch", with(func(f *WorktreeEndFacts) { f.OnBranch = false }), WorktreeEndKeep, false},
		{"nested repository", with(func(f *WorktreeEndFacts) { f.NestedRepo = "a gitlink at sub" }), WorktreeEndKeep, false},
		{"nested repository, also dirty", with(func(f *WorktreeEndFacts) { f.NestedRepo = "a nested .git at x"; f.Dirty = true }), WorktreeEndKeep, false},
		{"dirty", with(func(f *WorktreeEndFacts) { f.Dirty = true; f.BranchTip = moved }), WorktreeEndKeep, false},
		{"clean, no commits", live, WorktreeEndRemoveAll, true},
		{"clean, with commits", with(func(f *WorktreeEndFacts) { f.BranchTip = moved }), WorktreeEndRemoveKeepBranch, false},
		{"clean, unknown base", with(func(f *WorktreeEndFacts) { f.Base = "" }), WorktreeEndRemoveKeepBranch, false},
	}
	for _, c := range cases {
		d := DecideWorktreeEnd(c.f)
		if d.Action != c.action || d.DeleteBranch != c.del || d.Reason == "" {
			t.Errorf("%s: %+v, want %s delete=%v", c.name, d, c.action, c.del)
		}
	}
}

func TestPlanWorktreeEnd(t *testing.T) {
	const base = "1111111111111111111111111111111111111111"
	req := WorktreeEndRequest{MainRoot: filepath.FromSlash("/home/u/repo"), WorkspaceDir: filepath.FromSlash("/w/run1/repo"), Branch: "observer-sandbox/run1/work", Base: base}
	git := func(args ...string) []string {
		return append([]string{"git", "-C", req.MainRoot, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never"}, args...)
	}
	steps, err := PlanWorktreeEnd(req, WorktreeEndDecision{Action: WorktreeEndRemoveAll, DeleteBranch: true})
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		git("worktree", "remove", "--", req.WorkspaceDir),
		git("update-ref", "-d", "refs/heads/observer-sandbox/run1/work", base),
	}
	if len(steps) != len(want) {
		t.Fatalf("steps = %v", steps)
	}
	for i := range want {
		if !reflect.DeepEqual(steps[i].Argv, want[i]) || !steps[i].Hardened {
			t.Errorf("step %d = %v (hardened %v), want %v hardened", i, steps[i].Argv, steps[i].Hardened, want[i])
		}
		for _, a := range steps[i].Argv {
			if a == "prune" {
				t.Errorf("step %d prunes the whole repository: %v", i, steps[i].Argv)
			}
		}
		for _, a := range steps[i].Argv {
			if a == "--force" || a == "-f" || a == "-D" {
				t.Errorf("step %d forces: %v", i, steps[i].Argv)
			}
		}
	}
	if steps, _ := PlanWorktreeEnd(req, WorktreeEndDecision{Action: WorktreeEndRemoveKeepBranch}); len(steps) != 1 {
		t.Fatalf("keep-branch steps = %v", steps)
	}
	// A registration whose directory is gone is the cmd seam's to remove
	// (this run's admin dir only): no git step, except the branch delete.
	if steps, _ := PlanWorktreeEnd(req, WorktreeEndDecision{Action: WorktreeEndPruneOnly}); len(steps) != 0 {
		t.Fatalf("prune-only steps = %v", steps)
	}
	if steps, _ := PlanWorktreeEnd(req, WorktreeEndDecision{Action: WorktreeEndPruneOnly, DeleteBranch: true}); len(steps) != 1 || !reflect.DeepEqual(steps[0].Argv, git("update-ref", "-d", "refs/heads/observer-sandbox/run1/work", base)) {
		t.Fatalf("prune-only delete steps = %v", steps)
	}
	if steps, _ := PlanWorktreeEnd(req, WorktreeEndDecision{Action: WorktreeEndKeep}); len(steps) != 0 {
		t.Fatalf("keep steps = %v", steps)
	}
	bad := req
	bad.Branch = "main"
	if _, err := PlanWorktreeEnd(bad, WorktreeEndDecision{Action: WorktreeEndPruneOnly, DeleteBranch: true}); err == nil {
		t.Fatal("deleting a branch that is not a worktree run's was planned")
	}
	bad = req
	bad.Base = ""
	if _, err := PlanWorktreeEnd(bad, WorktreeEndDecision{Action: WorktreeEndRemoveAll, DeleteBranch: true}); err == nil {
		t.Fatal("deleting a branch with no base to compare was planned")
	}
}
