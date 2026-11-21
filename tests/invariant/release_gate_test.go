package invariant

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestReleaseGateNarrowedRunNeedsAQualifiedBase pins P-222 (2026-11-01):
// scripts/release.sh accepts a NARROWED ci dispatch (run title
// "ci narrowed since <base>") for a repeat release commit only when <base>
// has a green FULL dispatch on main, is an ancestor of the commit and comes
// after the previous release tag; a full run still passes as before. The
// gate functions (scripts/ci/release-gate.sh) run against a throwaway git
// history and a fake gh that serves canned run records per commit.
func TestReleaseGateNarrowedRunNeedsAQualifiedBase(t *testing.T) {
	root := repoRoot(t)
	if runtime.GOOS == "windows" {
		t.Skip("release.sh runs on a POSIX host")
	}
	for _, tool := range []string{"bash", "git", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not on PATH")
		}
	}
	repo := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"}, args...)...)
		cmd.Dir = repo
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	commit := func(msg string) string {
		git("commit", "-q", "--allow-empty", "-m", msg)
		return git("rev-parse", "HEAD")
	}
	git("init", "-q")
	rel := commit("previous release")
	git("branch", "-M", "main") // git init -b needs git 2.28
	git("tag", "v1.0.0")
	first := commit("first release commit of the cycle")
	mid := commit("fix forward")
	head := commit("second fix forward")
	git("checkout", "-q", "-b", "side", rel)
	side := commit("off main")
	git("checkout", "-q", "main")

	// Fake gh: `gh run list ... --commit <sha> ...` prints runs/<sha>.json,
	// or [] when there is none.
	runs := filepath.Join(t.TempDir(), "runs")
	bin := t.TempDir()
	if err := os.MkdirAll(runs, 0o755); err != nil {
		t.Fatal(err)
	}
	fake := "#!/usr/bin/env bash\nsha=\"\"\nwhile [ $# -gt 0 ]; do [ \"$1\" = --commit ] && sha=$2; shift; done\n" +
		"f=\"" + runs + "/$sha.json\"\nif [ -f \"$f\" ]; then cat \"$f\"; else echo '[]'; fi\n"
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(title, concl string) string {
		return `{"status":"completed","conclusion":"` + concl + `","event":"workflow_dispatch","headBranch":"main","displayTitle":"` + title + `"}`
	}
	serve := func(sha string, records ...string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(runs, sha+".json"), []byte("["+strings.Join(records, ",")+"]"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	reset := func() {
		t.Helper()
		ents, _ := os.ReadDir(runs)
		for _, e := range ents {
			_ = os.Remove(filepath.Join(runs, e.Name()))
		}
	}
	verdict := func(sha string) string {
		t.Helper()
		script := `. scripts/ci/release-gate.sh; GATE_REPO=o/r GATE_GIT="$1" GATE_GO_ROOT="$2"; gate_ci_verdict "$3"`
		cmd := exec.Command("bash", "-c", script, "gate", repo, root, sha)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("gate_ci_verdict %s: %v\n%s", sha[:9], err, out)
		}
		return strings.TrimSpace(string(out))
	}
	narrowed := func(base string) string { return run("ci narrowed since "+base, "success") }

	cases := []struct {
		name  string
		setup func()
		want  string
	}{
		{"a green full run passes", func() { serve(head, run("ci", "success")) }, "success"},
		{"no run", func() {}, "none"},
		{"a red full run", func() { serve(head, run("ci", "failure")) }, "failed:failure"},
		{"narrowed against the cycle's green full run passes", func() {
			serve(head, narrowed(first))
			serve(first, run("ci", "success"))
		}, "success-narrowed " + first},
		{"narrowed against a base whose full run is red", func() {
			serve(head, narrowed(first))
			serve(first, run("ci", "failure"))
		}, "narrowed-refused: base " + first[:9] + " has no green FULL dispatch on main"},
		{"narrowed against a base that was itself only narrowed", func() {
			serve(head, narrowed(mid))
			serve(mid, narrowed(first))
			serve(first, run("ci", "success"))
		}, "narrowed-refused: base " + mid[:9] + " has no green FULL dispatch on main"},
		{"narrowed against a commit off main's history", func() {
			serve(head, narrowed(side))
			serve(side, run("ci", "success"))
		}, "narrowed-refused: base " + side[:9] + " is not an ancestor of " + head[:9]},
		{"narrowed against the previous release itself (first commit of a cycle needs full)", func() {
			serve(head, narrowed(rel))
			serve(rel, run("ci", "success"))
		}, "narrowed-refused: base " + rel[:9] + " is not after the previous release v1.0.0: the first release commit of a cycle needs a full run"},
		{"a full run wins over a refused narrowed one", func() {
			serve(head, narrowed(rel), run("ci", "success"))
		}, "success"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reset()
			c.setup()
			if got := verdict(head); got != c.want {
				t.Errorf("verdict = %q, want %q", got, c.want)
			}
		})
	}
}
