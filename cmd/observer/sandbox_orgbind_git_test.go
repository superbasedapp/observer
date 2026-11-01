//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// mkGitDir makes <dir>/.git with a config and a hooks dir.
func mkGitDir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ".git", "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "config"), []byte("[core]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestSandboxOrgBindFindsNestedRepositories (P-054 follow-up, milestone 5;
// lane LEFT-SBX): under an org write bind, repositories two, three, four and
// five levels down are found and their hooks and config re-bound read-only
// (depth is bounded by the walk's budget, not by four levels, ledger
// SBX-GOV-3); a repository directly inside a found repository is found as
// before.
func TestSandboxOrgBindFindsNestedRepositories(t *testing.T) {
	bind := t.TempDir()
	two := filepath.Join(bind, "org", "repo")
	three := filepath.Join(bind, "a", "b", "c")
	four := filepath.Join(bind, "w", "x", "y", "z")
	inner := filepath.Join(two, "vendored")
	five := filepath.Join(bind, "p", "q", "r", "s", "t")
	for _, d := range []string{two, three, four, inner, five} {
		mkGitDir(t, d)
	}
	repos, err := sandboxOrgBindRepoCandidates(bind)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{two, three, four, inner, five} {
		if !slices.Contains(repos, want) {
			t.Errorf("repository %s not found under the bind (found %v)", want, repos)
		}
	}

	r := &sandboxRuntime{
		cfg:         config.TerminalSandboxConfig{ExtraRWBinds: []string{bind}, AllowToolConfigWrites: true},
		observerDir: filepath.Join(t.TempDir(), "obs"),
		orgRWBinds:  []string{bind},
	}
	ws := t.TempDir()
	ovs, err := r.overlays(filepath.Join(t.TempDir(), "home"), ws, integration.SandboxSpec{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]sandbox.OverlayKind{}
	for _, o := range ovs {
		got[o.Path] = o.Kind
	}
	for _, repo := range []string{two, three, four, inner, five} {
		for _, p := range []string{filepath.Join(repo, ".git", "config"), filepath.Join(repo, ".git", "hooks")} {
			if k, ok := got[p]; !ok || k != sandbox.OverlayReadOnly {
				t.Errorf("%s: overlay %v (present %v), want read-only", p, k, ok)
			}
		}
	}
}

// TestSandboxOrgBindWalkCapRefuses (milestone 5, budget per ruling P-060):
// a bind whose walk hits a cap refuses the launch naming the bind, never a
// silent skip: more directories within the depth than the 20000 budget, or
// one directory with too many entries.
func TestSandboxOrgBindWalkCapRefuses(t *testing.T) {
	if sandboxOrgBindScanCap != 20000 {
		t.Fatalf("the org-bind walk budget is %d, ruling P-060 sets 20000", sandboxOrgBindScanCap)
	}
	// 160 folders of 126 each: 20,321 directory reads, none past the entry
	// cap, so the refusal is the budget's.
	wide := t.TempDir()
	for i := 0; i < 160; i++ {
		for j := 0; j < 126; j++ {
			if err := os.MkdirAll(filepath.Join(wide, fmt.Sprintf("a%03d", i), fmt.Sprintf("b%03d", j)), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := sandboxOrgBindRepoCandidates(wide); err == nil || !strings.Contains(err.Error(), wide) || !strings.Contains(err.Error(), fmt.Sprintf("more than %d directories", sandboxOrgBindScanCap)) {
		t.Fatalf("a bind past the directory budget: %v, want a refusal naming %s", err, wide)
	}
	r := &sandboxRuntime{
		cfg:         config.TerminalSandboxConfig{ExtraRWBinds: []string{wide}},
		observerDir: filepath.Join(t.TempDir(), "obs"),
		orgRWBinds:  []string{wide},
	}
	if _, err := r.overlays(filepath.Join(t.TempDir(), "home"), t.TempDir(), integration.SandboxSpec{}); err == nil || !strings.Contains(err.Error(), wide) || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("the launch over a bind past the cap: %v", err)
	}

}

// TestSandboxOrgBindGoBuildCacheLaunches (ruling P-060, SBX-WORKTREE-SOURCE
// audit finding 3): an org write bind shaped like ~/.cache/go-build (256
// two-hex folders of cache files, 257 directory reads) no longer refuses
// the launch.
func TestSandboxOrgBindGoBuildCacheLaunches(t *testing.T) {
	cache := t.TempDir()
	for i := 0; i < 256; i++ {
		d := filepath.Join(cache, fmt.Sprintf("%02x", i))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		for j := 0; j < 3; j++ {
			if err := os.WriteFile(filepath.Join(d, fmt.Sprintf("%02x%062d-a", i, j)), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, f := range []string{"README", "trim.txt"} {
		if err := os.WriteFile(filepath.Join(cache, f), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if repos, err := sandboxOrgBindRepoCandidates(cache); err != nil || len(repos) != 0 {
		t.Fatalf("a go-build-shaped bind: repos %v, err %v", repos, err)
	}
	r := &sandboxRuntime{
		cfg:         config.TerminalSandboxConfig{ExtraRWBinds: []string{cache}},
		observerDir: filepath.Join(t.TempDir(), "obs"),
		orgRWBinds:  []string{cache},
	}
	if _, err := r.overlays(filepath.Join(t.TempDir(), "home"), t.TempDir(), integration.SandboxSpec{}); err != nil {
		t.Fatalf("the launch over a go-build-shaped org bind: %v", err)
	}
}

// TestSandboxRepoPins (SBX-WORKTREE-SOURCE audit finding 4): every
// repository the walk finds under an org write bind gets its folder and its
// .git (directory or file) pinned, a bind that is itself a repository gets
// its .git pinned (the bind is already a mount point), a live workspace's
// .git is pinned, a managed copy's is not, and a pin outside the workspace
// and the write binds is dropped.
func TestSandboxRepoPins(t *testing.T) {
	bind := t.TempDir()
	repo := filepath.Join(bind, "team", "repo")
	mkGitDir(t, repo)
	ptr := filepath.Join(bind, "wt")
	if err := os.MkdirAll(ptr, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ptr, ".git"), []byte("gitdir: /elsewhere\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	self := t.TempDir()
	mkGitDir(t, self)
	ws := t.TempDir()
	mkGitDir(t, ws)
	managed := filepath.Join(t.TempDir(), "workspaces")
	r := &sandboxRuntime{
		cfg:         config.TerminalSandboxConfig{ExtraRWBinds: []string{bind, self}, AllowToolConfigWrites: true},
		observerDir: filepath.Join(t.TempDir(), "obs"),
		orgRWBinds:  []string{bind, self},
		managedRoot: managed,
	}
	home := filepath.Join(t.TempDir(), "home")
	_, pins, err := r.protection(home, ws, integration.SandboxSpec{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{repo, filepath.Join(repo, ".git"), ptr, filepath.Join(ptr, ".git"), filepath.Join(self, ".git"), filepath.Join(ws, ".git")} {
		if !slices.Contains(pins, want) {
			t.Errorf("%s is not pinned (pins %v)", want, pins)
		}
	}
	if slices.Contains(pins, self) {
		t.Errorf("a bind that is itself a repository was pinned again: %v", pins)
	}
	copyWS := filepath.Join(managed, "id", "repo")
	mkGitDir(t, copyWS)
	if _, pins, err = r.protection(home, copyWS, integration.SandboxSpec{}); err != nil || slices.Contains(pins, filepath.Join(copyWS, ".git")) {
		t.Errorf("a managed copy's .git: pins %v, err %v", pins, err)
	}
	r.cfg.ExtraRWBinds = []string{self}
	if _, pins, err = r.protection(home, ws, integration.SandboxSpec{}); err != nil || slices.Contains(pins, repo) || slices.Contains(pins, filepath.Join(repo, ".git")) {
		t.Errorf("a pin outside every write bind was kept: %v %v", pins, err)
	}
}

// mkSubmoduleGitDir makes a git dir shaped like git's own (HEAD, objects,
// refs, config, hooks) at dir.
func mkSubmoduleGitDir(t *testing.T, dir string) {
	t.Helper()
	for _, d := range []string{"objects", "refs", "hooks"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"HEAD", "config"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestSandboxOrgBindProtectsSubmoduleGitDirs (SHR-WORKTREE2 milestone 5,
// lane SHR-FOLLOWUPS): a repository under an org write bind keeps its
// submodules' git dirs in .git/modules; each one (a plain name, a name with
// slashes, a nested submodule in its parent's own modules folder) is git
// data like the repository's .git: config and hooks read-only, the git dir
// and every folder on the way to it pinned. A folder there that is not a
// git dir is not protected, and the walk does not enter a git dir's
// objects.
func TestSandboxOrgBindProtectsSubmoduleGitDirs(t *testing.T) {
	bind := t.TempDir()
	repo := filepath.Join(bind, "proj")
	mkGitDir(t, repo)
	mods := filepath.Join(repo, ".git", "modules")
	plain := filepath.Join(mods, "lib")
	slashed := filepath.Join(mods, "third_party", "zlib")
	nested := filepath.Join(plain, "modules", "inner")
	decoyObjects := filepath.Join(plain, "objects", "ab")
	notGit := filepath.Join(mods, "stray")
	for _, d := range []string{plain, slashed, nested} {
		mkSubmoduleGitDir(t, d)
	}
	for _, d := range []string{decoyObjects, notGit} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A git-dir-shaped folder inside objects is never treated as one (the
	// walk stays out of a git dir's object store).
	mkSubmoduleGitDir(t, filepath.Join(decoyObjects, "fake"))

	rows, pins, err := sandboxOrgBindGitRows([]string{bind}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]protectedRow{}
	for _, r := range rows {
		got[r.path] = r
	}
	for _, gd := range []string{plain, slashed, nested} {
		for _, p := range []struct {
			path string
			dir  bool
		}{{filepath.Join(gd, "config"), false}, {filepath.Join(gd, "hooks"), true}} {
			r, ok := got[p.path]
			if !ok || r.kind != sandbox.OverlayReadOnly || r.dir != p.dir || r.remedy != remedyOrgWriteBind {
				t.Errorf("%s: row %+v (present %v), want a read-only org row", p.path, r, ok)
			}
		}
		if !slices.Contains(pins, gd) {
			t.Errorf("submodule git dir %s not pinned (pins %v)", gd, pins)
		}
	}
	for _, p := range []string{mods, filepath.Join(mods, "third_party"), filepath.Join(plain, "modules")} {
		if !slices.Contains(pins, p) {
			t.Errorf("folder %s on the way to a submodule git dir not pinned (pins %v)", p, pins)
		}
	}
	for _, p := range []string{notGit, filepath.Join(decoyObjects, "fake")} {
		if slices.Contains(pins, p) {
			t.Errorf("%s pinned; it is not a submodule git dir", p)
		}
		if _, ok := got[filepath.Join(p, "config")]; ok {
			t.Errorf("%s protected; it is not a submodule git dir", p)
		}
	}

	// With the submodule git dirs removed the same repository yields only
	// its own .git rows: the new rows come from .git/modules alone.
	if err := os.RemoveAll(mods); err != nil {
		t.Fatal(err)
	}
	rows2, _, err := sandboxOrgBindGitRows([]string{bind}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows2) != len(sandbox.WorkspaceExecState) {
		t.Fatalf("without .git/modules: %d rows, want %d", len(rows2), len(sandbox.WorkspaceExecState))
	}
}

// TestSandboxOrgBindModulesWalkSharesTheBudget (lane LEFT-SBX, ledger
// SBX-GOV-3 "one budget shared across the whole walk"): a .git/modules
// folder with more entries than one page is read in pages and launches, and
// the modules walk spends the bind walk's one budget, so a bind whose own
// walk is just under the budget refuses once its repository's modules push
// it past, naming the bind.
func TestSandboxOrgBindModulesWalkSharesTheBudget(t *testing.T) {
	bind := t.TempDir()
	mkGitDir(t, bind)
	mods := filepath.Join(bind, ".git", "modules")
	if err := os.MkdirAll(mods, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < sandboxOrgBindPageSize+1; i++ {
		if err := os.WriteFile(filepath.Join(mods, fmt.Sprintf("f%05d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := sandboxOrgBindGitRows([]string{bind}, nil); err != nil {
		t.Fatalf("a .git/modules over one page refused: %v", err)
	}

	w := &orgBindWalk{bind: bind, reads: sandboxOrgBindScanCap - 1}
	if _, _, err := w.moduleGitDirs(filepath.Join(bind, ".git")); err == nil || !strings.Contains(err.Error(), bind) || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("a modules walk past the shared budget: %v, want a refusal naming %s", err, bind)
	}
	if _, _, err := sandboxLinkedWorktreeRows(filepath.Join(bind, ".git"), remedyOrgWriteBind, &orgBindWalk{bind: bind, reads: sandboxOrgBindScanCap}); err != nil {
		t.Fatalf("no worktrees folder spends nothing: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(bind, ".git", "worktrees", "wt1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sandboxLinkedWorktreeRows(filepath.Join(bind, ".git"), remedyOrgWriteBind, &orgBindWalk{bind: bind, reads: sandboxOrgBindScanCap}); err == nil || !strings.Contains(err.Error(), bind) {
		t.Fatalf("a worktree listing past the shared budget: %v", err)
	}
}

// TestSandboxOrgBindLargeFolderLaunches (lane LEFT-SBX, the P-082 residual):
// a 5000-entry cache folder below an org bind is read in two pages within
// the budget and the launch goes ahead, where the old per-folder cap of 4096
// entries refused it; a repository next to it is still found and protected.
func TestSandboxOrgBindLargeFolderLaunches(t *testing.T) {
	bind := t.TempDir()
	cache := filepath.Join(bind, "cache", "blobs")
	if err := os.MkdirAll(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5000; i++ {
		if err := os.WriteFile(filepath.Join(cache, fmt.Sprintf("b%05d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	repo := filepath.Join(bind, "src", "app")
	mkGitDir(t, repo)
	w := &orgBindWalk{bind: bind}
	repos, err := w.repoCandidates()
	if err != nil || !slices.Contains(repos, repo) {
		t.Fatalf("repos %v, err %v", repos, err)
	}
	// bind, cache, cache/blobs (two pages), src, src/app.
	if w.reads != 6 {
		t.Errorf("the walk spent %d reads, want 6 (a 5000-entry folder is two pages)", w.reads)
	}
	r := &sandboxRuntime{
		cfg:         config.TerminalSandboxConfig{ExtraRWBinds: []string{bind}},
		observerDir: filepath.Join(t.TempDir(), "obs"),
		orgRWBinds:  []string{bind},
	}
	ovs, err := r.overlays(filepath.Join(t.TempDir(), "home"), t.TempDir(), integration.SandboxSpec{})
	if err != nil {
		t.Fatalf("the launch over a 5000-entry folder below an org bind: %v", err)
	}
	found := false
	for _, o := range ovs {
		found = found || o.Path == filepath.Join(repo, ".git", "config")
	}
	if !found {
		t.Error("the repository beside the large folder lost its read-only config")
	}
}

// TestSandboxOrgBindBudgetRefusalNamesTheRemedy (ruling P-141 part 2): the
// full-depth walk still fails closed over its budget, and the refusal names
// the bind, the count read and the remedy (skip_repo_scan).
func TestSandboxOrgBindBudgetRefusalNamesTheRemedy(t *testing.T) {
	bind := t.TempDir()
	w := &orgBindWalk{bind: bind, reads: sandboxOrgBindScanCap}
	err := w.charge()
	if err == nil {
		t.Fatal("a read past the budget was not refused")
	}
	for _, want := range []string{bind, fmt.Sprintf("more than %d directories", sandboxOrgBindScanCap), fmt.Sprintf("read %d", sandboxOrgBindScanCap), "skip_repo_scan", "refused"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
	if err := (&orgBindWalk{bind: bind, reads: sandboxOrgBindScanCap - 1}).charge(); err != nil {
		t.Errorf("the last read of the budget was refused: %v", err)
	}
}
