package git

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// updateGolden rewrites testdata/resolve_golden.json from the current code.
// The committed file was captured from the code before the linked-worktree
// fix (F0-14, lane shr-worktree), so it pins that the fix changes nothing
// for a repository that is not a linked worktree.
var updateGolden = flag.Bool("update-golden", false, "rewrite testdata/resolve_golden.json")

// goldenInfo is the subset of Info that existed before F0-14. CheckoutRoot
// is left out on purpose: it is new, and TestResolveGolden asserts it
// separately (it equals Root for every golden case).
type goldenInfo struct {
	Root   string `json:"root"`
	IsGit  bool   `json:"is_git"`
	Branch string `json:"branch"`
	Remote string `json:"remote"`
}

type goldenIdentity struct {
	goldenInfo
	UpstreamRemote     string `json:"upstream_remote"`
	RemoteOwner        string `json:"remote_owner"`
	UpstreamOwner      string `json:"upstream_owner"`
	RootCommitSHA      string `json:"root_commit_sha"`
	ContentFingerprint string `json:"content_fingerprint"`
	Workspace          string `json:"workspace"`
	IsWorktree         bool   `json:"is_worktree"`
}

type goldenCase struct {
	Name     string         `json:"name"`
	Resolve  goldenInfo     `json:"resolve"`
	FindRoot string         `json:"find_root"`
	FindOK   bool           `json:"find_ok"`
	Identity goldenIdentity `json:"identity"`
}

// buildGoldenFixtures lays out the fixture tree under base and returns
// the directories to resolve, in a fixed order.
func buildGoldenFixtures(t *testing.T, base string) []struct{ name, dir string } {
	t.Helper()
	repo := filepath.Join(base, "repo")
	makeRepo(t, repo, "main", "git@github.com:Example/Repo.git")
	appendRemote(t, repo, "upstream", "https://github.com/UpstreamOrg/Repo")
	mustWrite := func(p, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(filepath.Join(repo, "go.mod"), "module example.com/repo\n\ngo 1.22\n")
	mustWrite(filepath.Join(repo, "cmd", "main.go"), "package main\n")
	mustWrite(filepath.Join(repo, "pkg", "sub", "package.json"), `{"name":"sub"}`)
	mustWrite(filepath.Join(repo, "pkg", "sub", "deep", "x.txt"), "x")

	plain := filepath.Join(base, "plain")
	mustWrite(filepath.Join(plain, "notes", "a.txt"), "a")

	detached := filepath.Join(base, "detached")
	if err := os.MkdirAll(filepath.Join(detached, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(filepath.Join(detached, ".git", "HEAD"), "0123456789abcdef0123456789abcdef01234567\n")
	mustWrite(filepath.Join(detached, ".git", "config"), "[remote \"origin\"]\n\turl = https://gitlab.example.com/acme/detached.git\n")
	mustWrite(filepath.Join(detached, "src", "y.go"), "package src\n")

	cases := []struct{ name, dir string }{
		{"repo_root", repo},
		{"repo_subdirectory", filepath.Join(repo, "pkg", "sub", "deep")},
		{"non_git", plain},
		{"non_git_subdirectory", filepath.Join(plain, "notes")},
		{"detached_head", filepath.Join(detached, "src")},
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(filepath.Join(repo, "pkg", "sub"), link); err == nil {
		cases = append(cases, struct{ name, dir string }{"symlinked_path", link})
	}
	return cases
}

// goldenRel rewrites a path under base as "$BASE/..." in slash form.
func goldenRel(base, p string) string {
	if p == "" {
		return ""
	}
	if p == base {
		return "$BASE"
	}
	if strings.HasPrefix(p, base+string(filepath.Separator)) {
		return "$BASE/" + filepath.ToSlash(p[len(base)+1:])
	}
	return filepath.ToSlash(p)
}

// TestResolveGolden pins Resolve, FindRoot and ResolveIdentity's output for
// every repository shape the linked-worktree fix must leave alone: a normal
// repository, a subdirectory, a directory outside git, a symlinked path and
// a detached HEAD.
func TestResolveGolden(t *testing.T) {
	t.Parallel()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var got []goldenCase
	for _, c := range buildGoldenFixtures(t, base) {
		info, err := Resolve(c.dir)
		if err != nil {
			t.Fatalf("%s: Resolve: %v", c.name, err)
		}
		root, ok := FindRoot(c.dir)
		id, err := ResolveIdentity(c.dir, IdentityOptions{})
		if err != nil {
			t.Fatalf("%s: ResolveIdentity: %v", c.name, err)
		}
		gc := goldenCase{
			Name:     c.name,
			Resolve:  goldenInfo{Root: goldenRel(base, info.Root), IsGit: info.IsGit, Branch: info.Branch, Remote: info.Remote},
			FindRoot: goldenRel(base, root),
			FindOK:   ok,
			Identity: goldenIdentity{
				goldenInfo:     goldenInfo{Root: goldenRel(base, id.Root), IsGit: id.IsGit, Branch: id.Branch, Remote: id.Remote},
				UpstreamRemote: id.UpstreamRemote, RemoteOwner: id.RemoteOwner, UpstreamOwner: id.UpstreamOwner,
				RootCommitSHA: id.RootCommitSHA, ContentFingerprint: id.ContentFingerprint,
				Workspace: id.Workspace, IsWorktree: id.IsWorktree,
			},
		}
		got = append(got, gc)
		goldenCheckoutRoot(t, c.name, info, id)
	}
	body, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, '\n')
	path := filepath.Join("testdata", "resolve_golden.json")
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v (run with -update-golden)", err)
	}
	if _, symlinked := findCase(got, "symlinked_path"); !symlinked {
		// A host that cannot create symlinks compares the cases it built.
		var all []goldenCase
		if err := json.Unmarshal(want, &all); err != nil {
			t.Fatal(err)
		}
		var kept []goldenCase
		for _, c := range all {
			if c.Name != "symlinked_path" {
				kept = append(kept, c)
			}
		}
		want, _ = json.MarshalIndent(kept, "", "  ")
		want = append(want, '\n')
	}
	if string(body) != string(want) {
		t.Errorf("resolve output drifted from the golden captured before F0-14\n got: %s\nwant: %s", body, want)
	}
}

func findCase(cs []goldenCase, name string) (goldenCase, bool) {
	for _, c := range cs {
		if c.Name == name {
			return c, true
		}
	}
	return goldenCase{}, false
}

// goldenCheckoutRoot asserts the fields added after the golden capture.
func goldenCheckoutRoot(t *testing.T, name string, info Info, id Identity) {
	t.Helper()
	if info.CheckoutRoot != info.Root {
		t.Errorf("%s: Resolve CheckoutRoot = %q, want Root %q", name, info.CheckoutRoot, info.Root)
	}
	if id.CheckoutRoot != id.Root {
		t.Errorf("%s: ResolveIdentity CheckoutRoot = %q, want Root %q", name, id.CheckoutRoot, id.Root)
	}
}
