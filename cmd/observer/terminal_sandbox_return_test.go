//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// returnFixture makes a source repository with one commit and a managed
// copy of it (clone --no-hardlinks, as the clone-local source does).
func returnFixture(t *testing.T) (workspace.ReturnRequest, func(args ...string) string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	root := t.TempDir()
	if real, err := filepath.EvalSymlinks(root); err == nil {
		root = real
	}
	src := filepath.Join(root, "src")
	managed := filepath.Join(root, "workspaces")
	copyDir := filepath.Join(managed, "RUN000000000001", "src")
	git := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e", "GIT_CONFIG_NOSYSTEM=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	if err := os.MkdirAll(src, 0o700); err != nil {
		t.Fatal(err)
	}
	git(src, "init", "-q")
	_ = os.WriteFile(filepath.Join(src, "a.txt"), []byte("one\n"), 0o600)
	git(src, "add", "a.txt")
	git(src, "commit", "-qm", "one")
	if err := os.MkdirAll(filepath.Dir(copyDir), 0o700); err != nil {
		t.Fatal(err)
	}
	git(root, "clone", "-q", "--no-hardlinks", "--", src, copyDir)
	req := workspace.ReturnRequest{SourceRepo: src, CopyDir: copyDir, ManagedRoot: managed, RunID: "RUN000000000001"}
	return req, func(args ...string) string { return git(copyDir, args...) }
}

// TestSandboxReturnLandsANewRefOnly: the box's commit comes back as
// refs/observer/sandbox/<run>; the source's branch and working tree are
// untouched, and the copy is kept.
func TestSandboxReturnLandsANewRefOnly(t *testing.T) {
	req, inCopy := returnFixture(t)
	_ = os.WriteFile(filepath.Join(req.CopyDir, "b.txt"), []byte("two\n"), 0o600)
	inCopy("add", "b.txt")
	inCopy("commit", "-qm", "two")
	want := inCopy("rev-parse", "HEAD")
	headBefore, _ := exec.Command("git", "-C", req.SourceRepo, "rev-parse", "HEAD").Output()

	res, err := sandboxReturn(context.Background(), req, runReturnGit, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Commit != want || res.NothingNew || res.Ref != workspace.ReturnRefPrefix+req.RunID {
		t.Fatalf("result %+v", res)
	}
	got, err := exec.Command("git", "-C", req.SourceRepo, "rev-parse", res.Ref).Output()
	if err != nil || strings.TrimSpace(string(got)) != want {
		t.Fatalf("ref %s = %q %v", res.Ref, got, err)
	}
	headAfter, _ := exec.Command("git", "-C", req.SourceRepo, "rev-parse", "HEAD").Output()
	if string(headAfter) != string(headBefore) {
		t.Fatal("the source's branch moved")
	}
	if _, err := os.Stat(filepath.Join(req.SourceRepo, "b.txt")); err == nil {
		t.Fatal("the return wrote into the working tree")
	}
	if _, err := os.Stat(req.CopyDir); err != nil {
		t.Fatal("the copy was deleted")
	}
	// The ref is written create-only: a second return of the same run is
	// refused, never an update.
	_ = os.WriteFile(filepath.Join(req.CopyDir, "c.txt"), []byte("three\n"), 0o600)
	inCopy("add", "c.txt")
	inCopy("commit", "-qm", "three")
	if _, err := sandboxReturn(context.Background(), req, runReturnGit, nil); err == nil {
		t.Fatal("an existing ref was updated")
	}
	if got2, _ := exec.Command("git", "-C", req.SourceRepo, "rev-parse", res.Ref).Output(); strings.TrimSpace(string(got2)) != want {
		t.Fatal("the existing ref moved")
	}
}

// TestSandboxReturnScanOrder: the injected scan runs after the objects are
// in and BEFORE the ref is written; its refusal leaves no ref; a nil scan
// changes nothing.
func TestSandboxReturnScanOrder(t *testing.T) {
	req, inCopy := returnFixture(t)
	_ = os.WriteFile(filepath.Join(req.CopyDir, "secret.txt"), []byte("AKIA...\n"), 0o600)
	inCopy("add", "secret.txt")
	inCopy("commit", "-qm", "secret")
	sha := inCopy("rev-parse", "HEAD")

	var order []string
	run := func(ctx context.Context, st workspace.Step) ([]byte, error) {
		for _, a := range st.Argv {
			if a == "fetch" || a == "update-ref" {
				order = append(order, a)
			}
		}
		return runReturnGit(ctx, st)
	}
	scan := func(_ context.Context, in sandboxReturnScanInput) error {
		order = append(order, "scan")
		// The commit is already readable in the source when the scan runs.
		if err := exec.Command("git", "-C", in.Repo, "cat-file", "-e", in.Commit+"^{commit}").Run(); err != nil {
			t.Errorf("the scan ran before the objects were in: %v", err)
		}
		if in.Commit != sha || in.Ref != workspace.ReturnRefPrefix+req.RunID {
			t.Errorf("scan input %+v", in)
		}
		return errors.New("a secret is staged")
	}
	if _, err := sandboxReturn(context.Background(), req, run, scan); err == nil || !strings.Contains(err.Error(), "secret") {
		t.Fatalf("err %v", err)
	}
	if strings.Join(order, ",") != "fetch,scan" {
		t.Fatalf("order %v: the scan must come after the fetch and before any ref write", order)
	}
	if err := exec.Command("git", "-C", req.SourceRepo, "rev-parse", "--verify", "--quiet", workspace.ReturnRefPrefix+req.RunID).Run(); err == nil {
		t.Fatal("a refused return wrote the ref")
	}
	// nil scan: the same return lands.
	if res, err := sandboxReturn(context.Background(), req, runReturnGit, nil); err != nil || res.Commit != sha {
		t.Fatalf("%+v %v", res, err)
	}
}

// TestSandboxReturnNothingNew: a copy with no new commit writes no ref.
func TestSandboxReturnNothingNew(t *testing.T) {
	req, _ := returnFixture(t)
	res, err := sandboxReturn(context.Background(), req, runReturnGit, nil)
	if err != nil || !res.NothingNew {
		t.Fatalf("%+v %v", res, err)
	}
}

// TestSandboxReturnRefusesALinkedGitDir: a copy whose .git was replaced by
// a symlink (or a gitfile) is never followed.
func TestSandboxReturnRefusesALinkedGitDir(t *testing.T) {
	req, _ := returnFixture(t)
	gitDir := filepath.Join(req.CopyDir, ".git")
	if err := os.RemoveAll(gitDir); err != nil {
		t.Fatal(err)
	}
	if err := testSymlink(t, filepath.Join(req.SourceRepo, ".git"), gitDir); err != nil {
		t.Fatal(err)
	}
	if _, err := sandboxReturn(context.Background(), req, runReturnGit, nil); err == nil || !strings.Contains(err.Error(), "never followed") {
		t.Fatalf("err %v", err)
	}
}

// cannedReturnRunner answers the return's git steps from a table: the copy's
// HEAD, a commit the source lacks, a fetch that succeeds, the tree listing
// and the blobs, so the tree checks run without a git that knows every fetch
// flag.
func cannedReturnRunner(sha, tree string, blobs map[string]string) func(context.Context, workspace.Step) ([]byte, error) {
	return func(_ context.Context, st workspace.Step) ([]byte, error) {
		args := strings.Join(st.Argv, " ")
		switch {
		case strings.Contains(args, " config --list --show-origin --includes "):
			// The return scan's effective-config read: a clean clone.
			return []byte("file:.git/config\x00core.bare\nfalse\x00"), nil
		case strings.HasSuffix(args, " version"):
			return []byte("git version 2.45.0\n"), nil
		case strings.Contains(args, " ls-remote "):
			return []byte(sha + "\tHEAD\n"), nil
		case strings.Contains(args, " cat-file -e "):
			return nil, errors.New("missing")
		case strings.Contains(args, " fetch "):
			return nil, nil
		case strings.Contains(args, " ls-tree "):
			return []byte(tree), nil
		case strings.Contains(args, " cat-file blob "):
			return []byte(blobs[st.Argv[len(st.Argv)-1]]), nil
		case strings.Contains(args, " update-ref "):
			return nil, nil
		case strings.Contains(args, " rev-parse "):
			return []byte(sha + "\n"), nil
		}
		return nil, errors.New("unexpected step " + args)
	}
}

// TestSandboxReturnChecksSymlinksAndGitlinks (SBX-P3A merge finding F10): a
// returned symlink that points outside the tree, or a gitlink, refuses the
// return before any ref is written; an in-tree symlink lands.
func TestSandboxReturnChecksSymlinksAndGitlinks(t *testing.T) {
	root := t.TempDir()
	managed := filepath.Join(root, "workspaces")
	copyDir := filepath.Join(managed, "RUN000000000002", "src")
	if err := os.MkdirAll(filepath.Join(copyDir, ".git", "objects"), 0o700); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "src")
	_ = os.MkdirAll(src, 0o700)
	req := workspace.ReturnRequest{SourceRepo: src, CopyDir: copyDir, ManagedRoot: managed, RunID: "RUN000000000002"}
	sha := strings.Repeat("c", 40)
	in, out, sub := strings.Repeat("1", 40), strings.Repeat("2", 40), strings.Repeat("3", 40)
	line := func(mode, typ, obj, p string) string { return mode + " " + typ + " " + obj + "\t" + p + "\x00" }
	blobs := map[string]string{in: "../a.txt", out: "../../../home/me/.ssh/id_ed25519"}
	for _, c := range []struct {
		name, tree, want string
	}{
		{"in-tree link", line("100644", "blob", in, "a.txt") + line("120000", "blob", in, "docs/link"), ""},
		{"link outside", line("120000", "blob", out, "docs/key"), "outside the returned tree"},
		{"gitlink", line("160000", "commit", sub, "vendor/lib"), "gitlink"},
	} {
		t.Run(c.name, func(t *testing.T) {
			wrote := false
			run := cannedReturnRunner(sha, c.tree, blobs)
			spy := func(ctx context.Context, st workspace.Step) ([]byte, error) {
				if strings.Contains(strings.Join(st.Argv, " "), " update-ref ") {
					wrote = true
				}
				return run(ctx, st)
			}
			_, err := sandboxReturn(context.Background(), req, spy, nil)
			if c.want == "" {
				if err != nil {
					t.Fatalf("an in-tree symlink was refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want %q", err, c.want)
			}
			if wrote {
				t.Fatal("a refused return wrote the ref")
			}
		})
	}
}

// TestCopyGitSizeCountsAlternates (SBX-P3A merge finding F10): the object
// directories the copy's alternates name (absolute, relative, and an
// alternate's own alternates) count toward the size cap, each once.
func TestCopyGitSizeCountsAlternates(t *testing.T) {
	root := t.TempDir()
	copyDir := filepath.Join(root, "copy")
	objs := filepath.Join(copyDir, ".git", "objects")
	if err := os.MkdirAll(filepath.Join(objs, "info"), 0o700); err != nil {
		t.Fatal(err)
	}
	base, err := copyGitSize(copyDir)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(dir string, n int) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(dir, "info"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "pack"), make([]byte, n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	far := filepath.Join(root, "far", "objects")
	near := filepath.Join(root, "near", "objects")
	nested := filepath.Join(root, "nested", "objects")
	mk(far, 1000)
	mk(near, 2000)
	mk(nested, 4000)
	rel, err := filepath.Rel(objs, near)
	if err != nil {
		t.Fatal(err)
	}
	alt := far + "\n" + rel + "\n# a comment\n" + far + "\n"
	if err := os.WriteFile(filepath.Join(objs, "info", "alternates"), []byte(alt), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(near, "info", "alternates"), []byte(nested+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := copyGitSize(copyDir)
	if err != nil {
		t.Fatal(err)
	}
	altBytes := int64(len(alt))
	if want := base + altBytes + 1000 + 2000 + 4000 + int64(len(nested)+1); got != want {
		t.Fatalf("size %d, want %d (the alternates' objects counted once each)", got, want)
	}
}

// oldGitRunner answers the version step as git 2.25 (this project's WSL host)
// and runs every other step with the real runner, so the older-git path is
// exercised whatever git the test host has.
func oldGitRunner(steps *[]string) func(context.Context, workspace.Step) ([]byte, error) {
	return func(ctx context.Context, st workspace.Step) ([]byte, error) {
		args := strings.Join(st.Argv, " ")
		if steps != nil {
			*steps = append(*steps, args)
		}
		if strings.HasSuffix(args, " version") {
			return []byte("git version 2.25.1\n"), nil
		}
		return runReturnGit(ctx, st)
	}
}

// TestSandboxReturnOnOlderGit: on git older than 2.29 the fetch carries no
// --no-write-fetch-head or --no-auto-maintenance (exit 129 there), keeps
// every check, and the source's FETCH_HEAD ends as it was: absent stays
// absent, and an existing one keeps its bytes and mode.
func TestSandboxReturnOnOlderGit(t *testing.T) {
	for _, existing := range []bool{false, true} {
		name := "no FETCH_HEAD"
		if existing {
			name = "an existing FETCH_HEAD"
		}
		t.Run(name, func(t *testing.T) {
			req, inCopy := returnFixture(t)
			_ = os.WriteFile(filepath.Join(req.CopyDir, "b.txt"), []byte("two\n"), 0o600)
			inCopy("add", "b.txt")
			inCopy("commit", "-qm", "two")
			want := inCopy("rev-parse", "HEAD")
			fh := filepath.Join(req.SourceRepo, ".git", "FETCH_HEAD")
			prev := []byte(strings.Repeat("0", 40) + "\t\tbranch 'main' of /elsewhere\n")
			if existing {
				if err := os.WriteFile(fh, prev, 0o640); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(fh, 0o640); err != nil {
					t.Fatal(err)
				}
			}
			var steps []string
			res, err := sandboxReturn(context.Background(), req, oldGitRunner(&steps), nil)
			if err != nil {
				t.Fatal(err)
			}
			if res.Commit != want {
				t.Fatalf("result %+v", res)
			}
			fetched := false
			for _, s := range steps {
				if !strings.Contains(s, " fetch ") {
					continue
				}
				fetched = true
				for _, bad := range []string{"--no-write-fetch-head", "--no-auto-maintenance"} {
					if strings.Contains(s, bad) {
						t.Errorf("the older-git fetch passes %s: %s", bad, s)
					}
				}
				for _, keep := range []string{"transfer.fsckObjects=true", "fetch.fsckObjects=true", "gc.auto=0", "maintenance.auto=false", "core.hooksPath=/dev/null", "--no-tags", "--no-recurse-submodules"} {
					if !strings.Contains(s, keep) {
						t.Errorf("the older-git fetch lost %s: %s", keep, s)
					}
				}
			}
			if !fetched {
				t.Fatalf("no fetch step: %q", steps)
			}
			got, err := exec.Command("git", "-C", req.SourceRepo, "rev-parse", res.Ref).Output()
			if err != nil || strings.TrimSpace(string(got)) != want {
				t.Fatalf("ref %s = %q %v", res.Ref, got, err)
			}
			b, err := os.ReadFile(fh)
			switch {
			case !existing && err == nil:
				t.Fatalf("the return left a FETCH_HEAD behind: %q", b)
			case existing && (err != nil || string(b) != string(prev)):
				t.Fatalf("the source's FETCH_HEAD changed: %q %v", b, err)
			}
			if existing {
				if fi, err := os.Stat(fh); err != nil || (posixModes && fi.Mode().Perm() != 0o640) {
					t.Fatalf("FETCH_HEAD mode %v %v", fi.Mode(), err)
				}
			}
			entries, _ := os.ReadDir(filepath.Join(req.SourceRepo, ".git"))
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), ".observer-return-") {
					t.Fatalf("a temporary file was left: %s", e.Name())
				}
			}
		})
	}
}

// TestSandboxReturnRefusesAnOddFetchHead: on older git a FETCH_HEAD that is
// not a regular file refuses the return before anything is fetched.
func TestSandboxReturnRefusesAnOddFetchHead(t *testing.T) {
	req, inCopy := returnFixture(t)
	_ = os.WriteFile(filepath.Join(req.CopyDir, "b.txt"), []byte("two\n"), 0o600)
	inCopy("add", "b.txt")
	inCopy("commit", "-qm", "two")
	if err := os.Mkdir(filepath.Join(req.SourceRepo, ".git", "FETCH_HEAD"), 0o700); err != nil {
		t.Fatal(err)
	}
	var steps []string
	if _, err := sandboxReturn(context.Background(), req, oldGitRunner(&steps), nil); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("err %v", err)
	}
	for _, s := range steps {
		if strings.Contains(s, " fetch ") || strings.Contains(s, " update-ref ") {
			t.Fatalf("a step ran after the refusal: %s", s)
		}
	}
}
