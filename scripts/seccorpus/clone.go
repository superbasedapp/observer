package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// cloneTimeout bounds one repository's fetch.
const cloneTimeout = 15 * time.Minute

// selfURL is this repository's URL in the corpus: it is taken from the
// local checkout (-self), never fetched.
const selfURL = "https://github.com/marmutapp/superbased-observer-private"

// outside reports whether dir lies outside root (both made absolute and
// symlink-resolved where they exist).
func outside(dir, root string) (bool, error) {
	ad, err := filepath.Abs(dir)
	if err != nil {
		return false, err
	}
	ar, err := filepath.Abs(root)
	if err != nil {
		return false, err
	}
	if r, err := filepath.EvalSymlinks(ar); err == nil {
		ar = r
	}
	if r, err := filepath.EvalSymlinks(ad); err == nil {
		ad = r
	}
	rel, err := filepath.Rel(ar, ad)
	if err != nil {
		return true, nil
	}
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)), nil
}

// gitEnv is git's environment for a clone: no hooks, no LFS smudge, no
// prompts, no system or global config.
func gitEnv() []string {
	return append(os.Environ(),
		"GIT_LFS_SKIP_SMUDGE=1", "GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
}

// git runs git with the hardening flags in dir.
func git(ctx context.Context, dir string, args ...string) (string, error) {
	full := append([]string{"-c", "core.hooksPath=" + os.DevNull, "-c", "protocol.file.allow=user",
		"-c", "core.fsmonitor=false", "-c", "advice.detachedHead=false"}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Dir = dir
	cmd.Env = gitEnv()
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// cloneOne fetches r at its commit into dir (an existing clone at the
// right commit is kept). Only HEAD's tree is fetched (depth 1).
func cloneOne(ctx context.Context, r repo, dir, self string) error {
	ctx, cancel := context.WithTimeout(ctx, cloneTimeout)
	defer cancel()
	if head, err := git(ctx, dir, "rev-parse", "HEAD"); err == nil && head == r.Commit {
		return nil
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	src := r.URL
	if r.URL == selfURL {
		abs, err := filepath.Abs(self)
		if err != nil {
			return err
		}
		src = abs
	}
	for _, step := range [][]string{
		{"init", "-q"},
		{"remote", "add", "origin", src},
		{"fetch", "-q", "--depth", "1", "--no-tags", "origin", r.Commit},
		{"checkout", "-q", "FETCH_HEAD"},
	} {
		if out, err := git(ctx, dir, step...); err != nil {
			return fmt.Errorf("git %s: %v: %s", step[0], err, firstLine(out))
		}
	}
	if head, err := git(ctx, dir, "rev-parse", "HEAD"); err != nil || head != r.Commit {
		return fmt.Errorf("checked out %q, want %s", head, r.Commit)
	}
	return nil
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// cloneAll clones every repository and records the result in clone.json.
func cloneAll(p paths, dest, self string) error {
	if dest == "" {
		return fmt.Errorf("clone: -dest is required")
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	if ok, err := outside(dest, root); err != nil || !ok {
		return fmt.Errorf("clone: %s must lie outside this checkout", dest)
	}
	repos, err := readRepos(p.file("repos.tsv"))
	if err != nil {
		return err
	}
	var rows []repoStatus
	for _, r := range repos {
		st := repoStatus{Repo: r.URL, Commit: r.Commit, Cloned: true}
		if err := cloneOne(context.Background(), r, filepath.Join(dest, r.dir()), self); err != nil {
			st.Cloned, st.Reason = false, "clone_failed: "+err.Error()
		}
		fmt.Printf("%-60s %v %s\n", r.URL, st.Cloned, st.Reason)
		rows = append(rows, st)
	}
	return writeJSON(p.file("clone.json"), rows)
}
