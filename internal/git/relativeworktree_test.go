package git

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// relativize rewrites a worktree made by WorktreeAdd into the layout git
// 2.48 writes under `worktree.useRelativePaths` (this host's git is older,
// PT-13): the worktree's `.git` file and the admin directory's back
// pointer hold paths relative to their own directories. Either half can
// be left absolute with relGitFile / relBack false.
func relativize(t *testing.T, wt string, relGitFile, relBack bool) {
	t.Helper()
	wtReal := realPath(t, wt)
	val, ok := readGitFileDir(filepath.Join(wtReal, ".git"))
	if !ok {
		t.Fatalf("no gitdir in %s/.git", wtReal)
	}
	admin := realPath(t, val)
	if relGitFile {
		rel, err := filepath.Rel(wtReal, admin)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(wtReal, ".git"), "gitdir: "+filepath.ToSlash(rel)+"\n")
	}
	if relBack {
		rel, err := filepath.Rel(admin, filepath.Join(wtReal, ".git"))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(admin, "gitdir"), filepath.ToSlash(rel)+"\n")
	}
}

func writeFile(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestRelativeWorktree_FoldsOntoMainProject: a relative-path worktree,
// outside or inside the main checkout, and with either pointer relative,
// resolves to the main repository's project with its own checkout and
// branch, exactly like an absolute one (lane shr-worktree2, PT-39).
func TestRelativeWorktree_FoldsOntoMainProject(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name              string
		inTree            bool
		relGitFile, relBk bool
	}{
		{"out_of_tree_both_relative", false, true, true},
		{"in_tree_both_relative", true, true, true},
		{"relative_git_file_absolute_back_pointer", false, true, false},
		{"absolute_git_file_relative_back_pointer", false, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			repo := mainWithRemotes(t)
			mainRoot := realPath(t, repo)
			mainID := wantResolved(t, repo, mainRoot, mainRoot, false)
			wt := filepath.Join(t.TempDir(), "wt")
			if c.inTree {
				wt = filepath.Join(repo, ".worktrees", "x")
			}
			branch := "rel/" + c.name
			if err := WorktreeAdd(ctx, repo, wt, branch, "HEAD"); err != nil {
				t.Fatalf("WorktreeAdd: %v", err)
			}
			relativize(t, wt, c.relGitFile, c.relBk)
			sub := filepath.Join(wt, "pkg")
			if err := os.MkdirAll(sub, 0o755); err != nil {
				t.Fatal(err)
			}
			id := wantResolved(t, sub, mainRoot, realPath(t, wt), true)
			if id.Branch != branch {
				t.Errorf("Branch = %q, want the worktree's own %q", id.Branch, branch)
			}
			if id.Remote != mainID.Remote || id.RootCommitSHA != mainID.RootCommitSHA || id.RootCommitSHA == "" {
				t.Errorf("identity differs from main: remote %q/%q root %q/%q", id.Remote, mainID.Remote, id.RootCommitSHA, mainID.RootCommitSHA)
			}
			if got, ok := LinkedCommonDir(wt); !ok || got != filepath.Join(mainRoot, ".git") {
				t.Errorf("LinkedCommonDir = %q %v", got, ok)
			}
		})
	}
}

// TestRelativeWorktree_Refused: a relative pointer that escapes, dangles,
// lands outside `<common>/worktrees`, or whose back pointer names another
// checkout is not followed; the directory resolves to itself, as any other
// unrecognised `.git` file does.
func TestRelativeWorktree_Refused(t *testing.T) {
	ctx := context.Background()
	repo := mainWithRemotes(t)
	mainRoot := realPath(t, repo)
	wt := filepath.Join(t.TempDir(), "wt")
	if err := WorktreeAdd(ctx, repo, wt, "refused/real", "HEAD"); err != nil {
		t.Fatalf("WorktreeAdd: %v", err)
	}
	relativize(t, wt, true, true)
	admin := filepath.Join(mainRoot, ".git", "worktrees", "wt")

	deep := strings.Repeat("../", 64)
	cases := []struct {
		name string
		// gitFile is written to <dir>/.git; dir is a fresh temp directory.
		gitFile func(dir string) string
	}{
		{"escapes_filesystem_root", func(string) string {
			return "gitdir: " + deep + filepath.ToSlash(strings.TrimPrefix(admin, filepath.VolumeName(admin))) + "\n"
		}},
		{"dangling", func(string) string { return "gitdir: ../no/such/.git/worktrees/wt\n" }},
		{"main_git_dir_not_a_worktree", func(dir string) string {
			return "gitdir: " + relFrom(t, dir, filepath.Join(mainRoot, ".git")) + "\n"
		}},
		{"real_admin_dir_back_pointer_elsewhere", func(dir string) string {
			return "gitdir: " + relFrom(t, dir, admin) + "\n"
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, ".git"), c.gitFile(realPath(t, dir)))
			dirReal := realPath(t, dir)
			id := wantResolved(t, dir, dirReal, dirReal, false)
			if id.Branch != "" || id.Remote != "" {
				t.Errorf("a refused pointer must not redirect reads, got %q %q", id.Branch, id.Remote)
			}
		})
	}

	// A real worktree whose back pointer escapes is refused too.
	t.Run("back_pointer_escapes", func(t *testing.T) {
		writeFile(t, filepath.Join(admin, "gitdir"), deep+"wt/.git\n")
		wtReal := realPath(t, wt)
		wantResolved(t, wt, wtReal, wtReal, false)
	})
}

func relFrom(t *testing.T, from, to string) string {
	t.Helper()
	rel, err := filepath.Rel(from, to)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.ToSlash(rel)
}

// TestResolveGitPointer pins the pointer spellings, including the Windows
// drive-letter forms, on the OS the test runs on.
func TestResolveGitPointer(t *testing.T) {
	base := filepath.FromSlash("/a/b/c")
	if runtime.GOOS == "windows" {
		base = `C:\a\b\c`
	}
	type tc struct {
		name, val, want string
		ok              bool
	}
	cases := []tc{
		{"empty", "", "", false},
		{"relative", "../x/.git/worktrees/w", filepath.Join(base, "..", "x", ".git", "worktrees", "w"), true},
		{"relative_to_root", "../../../x", filepath.Join(base, "..", "..", "..", "x"), true},
		{"climbs_above_root", "../../../../x", "", false},
		{"dot_segments", "./x/./y", filepath.Join(base, "x", "y"), true},
		{"backslash_relative", `..\x\y`, filepath.Join(base, "..", "x", "y"), runtime.GOOS == "windows"},
		{"unc_on_this_os", `\\server\share\x`, "", runtime.GOOS == "windows"},
		{"drive_relative", "C:x/y", "", false},
	}
	if runtime.GOOS == "windows" {
		cases = append(cases,
			tc{"drive_absolute_forward_slashes", "C:/r/.git/worktrees/w", `C:\r\.git\worktrees\w`, true},
			tc{"drive_absolute_dotdot", "C:/r/../r/.git/worktrees/w", "", false},
			tc{"rooted_no_drive", "/r/.git/worktrees/w", "", false},
		)
	} else {
		cases = append(cases,
			tc{"absolute", "/r/.git/worktrees/w", "/r/.git/worktrees/w", true},
			tc{"absolute_dotdot", "/r/../r/.git/worktrees/w", "", false},
			tc{"drive_absolute_read_on_unix", "C:/r/.git/worktrees/w", "", false},
		)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := resolveGitPointer(base, c.val)
			if ok != c.ok || (ok && c.want != "" && got != c.want) {
				t.Errorf("resolveGitPointer(%q, %q) = %q %v, want %q %v", base, c.val, got, ok, c.want, c.ok)
			}
		})
	}
}

// TestRelativeWorktree_RealGit248 runs a real `git worktree add
// --relative-paths` where the host's git supports it (2.48 or newer;
// skipped below, PT-13).
func TestRelativeWorktree_RealGit248(t *testing.T) {
	gitAvailable(t)
	out, err := exec.Command("git", "version").Output()
	if err != nil || !gitAtLeast(string(out), 2, 48) {
		t.Skipf("git %q is older than 2.48: no --relative-paths", strings.TrimSpace(string(out)))
	}
	repo := mainWithRemotes(t)
	mainRoot := realPath(t, repo)
	for _, wt := range []string{filepath.Join(t.TempDir(), "wt"), filepath.Join(repo, ".worktrees", "x")} {
		runOrFail(t, repo, "worktree", "add", "--relative-paths", "-b", "real/"+filepath.Base(wt), wt, "HEAD")
		if body, _ := os.ReadFile(filepath.Join(wt, ".git")); filepath.IsAbs(strings.TrimSpace(strings.TrimPrefix(string(body), "gitdir:"))) {
			t.Fatalf("git wrote an absolute gitdir: %s", body)
		}
		wantResolved(t, wt, mainRoot, realPath(t, wt), true)
	}
}

// gitAtLeast parses `git version X.Y...` output.
func gitAtLeast(out string, major, minor int) bool {
	f := strings.Fields(out)
	if len(f) < 3 {
		return false
	}
	parts := strings.SplitN(f[2], ".", 3)
	if len(parts) < 2 {
		return false
	}
	ma, err1 := strconv.Atoi(parts[0])
	mi, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	return ma > major || ma == major && mi >= minor
}

// TestCheckoutRootTarget: only a linked worktree's own top level maps to
// its main project.
func TestCheckoutRootTarget(t *testing.T) {
	ctx := context.Background()
	repo := mainWithRemotes(t)
	mainRoot := realPath(t, repo)
	wt := filepath.Join(t.TempDir(), "wt")
	if err := WorktreeAdd(ctx, repo, wt, "crt/wt", "HEAD"); err != nil {
		t.Fatal(err)
	}
	relativize(t, wt, true, true)
	sub := filepath.Join(wt, "pkg")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, root, want string
		ok               bool
	}{
		{"relative-path worktree top level", realPath(t, wt), mainRoot, true},
		{"worktree subdirectory", realPath(t, sub), "", false},
		{"main checkout", mainRoot, "", false},
		{"legacy admin root", mainRoot + "/.git/worktrees", "", false},
		{"gone", filepath.Join(t.TempDir(), "gone"), "", false},
		{"relative", "wt", "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, ok := CheckoutRootTarget(c.root)
			if ok != c.ok || got != c.want {
				t.Errorf("CheckoutRootTarget(%q) = %q %v, want %q %v", c.root, got, ok, c.want, c.ok)
			}
		})
	}
}

// TestLinkedWorktreeCheckouts: every live worktree of the project, absolute
// or relative, in-tree or not; a stale admin directory, a back pointer to
// elsewhere and the cap are honoured; an ordinary repository has none.
func TestLinkedWorktreeCheckouts(t *testing.T) {
	ctx := context.Background()
	repo := mainWithRemotes(t)
	mainRoot := realPath(t, repo)
	if got := LinkedWorktreeCheckouts(mainRoot, 10); len(got) != 0 {
		t.Fatalf("no worktrees yet, got %v", got)
	}
	a := filepath.Join(t.TempDir(), "a")
	b := filepath.Join(repo, ".worktrees", "b")
	c := filepath.Join(t.TempDir(), "c")
	for i, w := range []string{a, b, c} {
		if err := WorktreeAdd(ctx, repo, w, "lwc/"+strconv.Itoa(i), "HEAD"); err != nil {
			t.Fatal(err)
		}
	}
	relativize(t, b, true, true)
	// c's checkout is removed without `git worktree prune`: stale.
	if err := os.RemoveAll(c); err != nil {
		t.Fatal(err)
	}
	// A planted admin directory whose back pointer names an unrelated dir.
	planted := filepath.Join(mainRoot, ".git", "worktrees", "zz")
	writeFile(t, filepath.Join(planted, "gitdir"), filepath.Join(t.TempDir(), ".git")+"\n")
	got := LinkedWorktreeCheckouts(mainRoot, 10)
	want := []string{realPath(t, a), realPath(t, b)}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("LinkedWorktreeCheckouts = %v, want %v", got, want)
	}
	if got := LinkedWorktreeCheckouts(mainRoot, 1); len(got) != 1 {
		t.Errorf("cap 1 gave %v", got)
	}
	if got := LinkedWorktreeCheckouts(mainRoot, 0); got != nil {
		t.Errorf("cap 0 gave %v", got)
	}
}
