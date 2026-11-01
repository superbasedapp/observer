//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// terminal_sandbox_oci_endrun_linux_test.go: the Linux live re-check 3 D3
// fix. Every clone-local return was refused naming Observer's own
// placeholders (commondir, config.worktree, info/attributes,
// objects/info/alternates), because the helper removed them only after the
// return step's scan of the copy's git dir.

// endRunFixture is a clone-local copy where the box committed, with the
// helper's placeholders made in it as startHostServices makes them.
func endRunFixture(t *testing.T, plant func(copyDir string)) (ociPlanFile, func()) {
	t.Helper()
	req, inCopy := returnFixture(t)
	if err := os.WriteFile(filepath.Join(req.CopyDir, "a.txt"), []byte("one\ntwo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inCopy("commit", "-qam", "box commit")
	if plant != nil {
		plant(req.CopyDir)
	}
	var files []string
	for _, pp := range sandbox.WorkspaceExecState {
		if !pp.Dir {
			files = append(files, filepath.Join(req.CopyDir, pp.Rel))
		}
	}
	stop, err := startHostServices(sandbox.HostArgs{PlaceholderFiles: files})
	if err != nil {
		stop()
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(req.CopyDir, ".git", "commondir")); err != nil {
		t.Fatalf("no commondir in the copy during the run: %v", err)
	}
	return ociPlanFile{Return: &req}, sync.OnceFunc(stop)
}

// TestOCIEndRunReturnsABoxThatOnlyCommits: the placeholders go first, so the
// return lands the box's commit; the old order (the return before the
// release) is what the live run saw.
func TestOCIEndRunReturnsABoxThatOnlyCommits(t *testing.T) {
	plan, release := endRunFixture(t, nil)
	tt := newOCITestTerm()
	ociEndRun(plan, tt.term, release)
	if out := tt.out.String(); !strings.Contains(out, "the box's commits are on refs/observer/") {
		t.Fatalf("a box that only committed was not returned: %q", out)
	}
	for _, rel := range []string{".git/commondir", ".git/config.worktree", ".git/info/attributes", ".git/objects/info/alternates"} {
		if _, err := os.Lstat(filepath.Join(plan.Return.CopyDir, rel)); err == nil {
			t.Errorf("the placeholder %s outlived the run", rel)
		}
	}

	old, oldRelease := endRunFixture(t, nil)
	tt2 := newOCITestTerm()
	ociAfterRun(old, tt2.term)
	oldRelease()
	if out := tt2.out.String(); !strings.Contains(out, "commondir") || !strings.Contains(out, "not returned") {
		t.Fatalf("the old order no longer reproduces D3: %q", out)
	}
}

// TestOCIEndRunStillRefusesAPlantedCommondir: a commondir the box wrote is
// never taken for a placeholder (the helper never made that inode), so the
// return still refuses it, naming it, and keeps the copy.
func TestOCIEndRunStillRefusesAPlantedCommondir(t *testing.T) {
	plan, release := endRunFixture(t, func(copyDir string) {
		if err := os.WriteFile(filepath.Join(copyDir, ".git", "commondir"), []byte("../evilc\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	tt := newOCITestTerm()
	ociEndRun(plan, tt.term, release)
	out := tt.out.String()
	if !strings.Contains(out, "not returned") || !strings.Contains(out, "commondir") {
		t.Fatalf("a planted commondir was returned: %q", out)
	}
	for _, other := range []string{"config.worktree", "info/attributes", "alternates"} {
		if strings.Contains(out, other) {
			t.Errorf("the refusal names Observer's own placeholder %s: %q", other, out)
		}
	}
	if _, err := os.Stat(plan.Return.CopyDir); err != nil {
		t.Fatalf("the copy was not kept: %v", err)
	}
}
