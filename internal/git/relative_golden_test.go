package git

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// updateRelGolden rewrites testdata/relative_golden.json. The committed
// file was captured before lane shr-worktree2 (PT-39: relative-path
// linked worktrees and the checkout path seam), so it pins that neither
// changes anything for a repository that is not a linked worktree:
// ordinary repositories, relative-gitdir `.git` files that are not
// worktrees (a submodule, a dangling or planted pointer), and the
// project-relative path of every kind of target.
var updateRelGolden = flag.Bool("update-relative-golden", false, "rewrite testdata/relative_golden.json")

type relGoldenResolve struct {
	Name    string     `json:"name"`
	Resolve goldenInfo `json:"resolve"`
	Find    string     `json:"find_root"`
	Check   string     `json:"find_checkout_root"`
}

type relGoldenPath struct {
	Name string `json:"name"`
	Got  string `json:"rel"`
}

type relGolden struct {
	Resolve []relGoldenResolve `json:"resolve"`
	Paths   []relGoldenPath    `json:"paths"`
}

// buildRelGoldenFixtures lays out repositories with relative `.git` file
// pointers that are NOT linked worktrees, and returns the directories to
// resolve and the (root, target) pairs to relativize, in a fixed order.
func buildRelGoldenFixtures(t *testing.T, base string) ([]struct{ name, dir string }, []struct{ name, root, target string }) {
	t.Helper()
	mustWrite := func(p, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	repo := filepath.Join(base, "repo")
	makeRepo(t, repo, "main", "git@github.com:Example/Repo.git")
	mustWrite(filepath.Join(repo, "pkg", "a.go"), "package pkg\n")

	// A submodule as modern git writes it: a relative gitdir into the
	// parent's .git/modules.
	mods := filepath.Join(repo, ".git", "modules", "sub")
	mustWrite(filepath.Join(mods, "HEAD"), "ref: refs/heads/subbranch\n")
	mustWrite(filepath.Join(mods, "config"), "[remote \"origin\"]\n\turl = https://example.com/sub.git\n")
	mustWrite(filepath.Join(repo, "sub", ".git"), "gitdir: ../.git/modules/sub\n")
	mustWrite(filepath.Join(repo, "sub", "s.go"), "package sub\n")

	// A relative pointer into a worktrees directory with no back pointer.
	admin := filepath.Join(repo, ".git", "worktrees", "nobp")
	mustWrite(filepath.Join(admin, "HEAD"), "ref: refs/heads/nobp\n")
	mustWrite(filepath.Join(admin, "commondir"), "../..\n")
	mustWrite(filepath.Join(base, "nobp", ".git"), "gitdir: ../repo/.git/worktrees/nobp\n")

	// A relative pointer whose back pointer names another checkout.
	admin2 := filepath.Join(repo, ".git", "worktrees", "other")
	mustWrite(filepath.Join(admin2, "HEAD"), "ref: refs/heads/other\n")
	mustWrite(filepath.Join(admin2, "commondir"), "../..\n")
	mustWrite(filepath.Join(admin2, "gitdir"), filepath.Join(base, "elsewhere", ".git")+"\n")
	mustWrite(filepath.Join(base, "elsewhere", ".git"), "gitdir: ../repo/.git/worktrees/other\n")
	mustWrite(filepath.Join(base, "planted", ".git"), "gitdir: ../repo/.git/worktrees/other\n")

	// A dangling relative pointer.
	mustWrite(filepath.Join(base, "dangling", ".git"), "gitdir: ../no/such/.git/worktrees/x\n")

	plain := filepath.Join(base, "plain")
	mustWrite(filepath.Join(plain, "n.txt"), "n")

	dirs := []struct{ name, dir string }{
		{"repo_root", repo},
		{"repo_pkg", filepath.Join(repo, "pkg")},
		{"submodule_relative_gitdir", filepath.Join(repo, "sub")},
		{"worktrees_pointer_no_back_pointer", filepath.Join(base, "nobp")},
		{"worktrees_pointer_back_pointer_elsewhere", filepath.Join(base, "planted")},
		{"dangling_relative_pointer", filepath.Join(base, "dangling")},
		{"non_git", plain},
	}
	paths := []struct{ name, root, target string }{
		{"in_repo", repo, filepath.Join(repo, "pkg", "a.go")},
		{"repo_root_itself", repo, repo},
		{"missing_in_repo", repo, filepath.Join(repo, "pkg", "new.go")},
		{"in_submodule", repo, filepath.Join(repo, "sub", "s.go")},
		{"outside_repo", repo, filepath.Join(plain, "n.txt")},
		{"in_planted_pointer", repo, filepath.Join(base, "planted", "x.go")},
		{"empty_target", repo, ""},
		{"non_git_root", plain, filepath.Join(plain, "n.txt")},
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(filepath.Join(repo, "pkg"), link); err == nil {
		paths = append(paths, struct{ name, root, target string }{"symlinked_target", repo, filepath.Join(link, "a.go")})
	}
	return dirs, paths
}

// TestRelativeGolden pins resolution and relativization for every shape
// the relative-path worktree recognizer and the checkout path seam must
// leave alone.
func TestRelativeGolden(t *testing.T) {
	t.Parallel()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dirs, paths := buildRelGoldenFixtures(t, base)
	var got relGolden
	for _, d := range dirs {
		info, err := Resolve(d.dir)
		if err != nil {
			t.Fatalf("%s: %v", d.name, err)
		}
		root, _ := FindRoot(d.dir)
		checkout, _ := FindCheckoutRoot(d.dir)
		got.Resolve = append(got.Resolve, relGoldenResolve{
			Name:    d.name,
			Resolve: goldenInfo{Root: goldenRel(base, info.Root), IsGit: info.IsGit, Branch: info.Branch, Remote: info.Remote},
			Find:    goldenRel(base, root),
			Check:   goldenRel(base, checkout),
		})
	}
	for _, p := range paths {
		got.Paths = append(got.Paths, relGoldenPath{Name: p.name, Got: relGoldenPathOf(p.root, p.target, base)})
	}
	body, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, '\n')
	path := filepath.Join("testdata", "relative_golden.json")
	if *updateRelGolden {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v (run with -update-relative-golden)", err)
	}
	if len(paths) > 0 && paths[len(paths)-1].name != "symlinked_target" {
		// A host that cannot create symlinks compares the cases it built.
		var all relGolden
		if err := json.Unmarshal(want, &all); err != nil {
			t.Fatal(err)
		}
		kept := all.Paths[:0]
		for _, p := range all.Paths {
			if p.Name != "symlinked_target" {
				kept = append(kept, p)
			}
		}
		all.Paths = kept
		want, _ = json.MarshalIndent(all, "", "  ")
		want = append(want, '\n')
	}
	if string(body) != string(want) {
		t.Errorf("output drifted from the golden captured before shr-worktree2\n got: %s\nwant: %s", body, want)
	}
}

// relGoldenPathOf is the project-relative path every adapter stores for
// target, with the fixture base spelled $BASE.
func relGoldenPathOf(root, target, base string) string {
	rel := CheckoutRelativePath(root, target)
	if after, ok := cutPrefixSlash(rel, "[external]/"+filepath.ToSlash(base)); ok {
		return "[external]/$BASE" + after
	}
	return rel
}

func cutPrefixSlash(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):], true
	}
	return "", false
}
