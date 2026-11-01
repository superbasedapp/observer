package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/platform/xcodehost"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Audit row 7 on the w13 hand-back (completes w13's row 8): the project
// audience matcher, the delivery "Check now" and the guidance scanner never
// resolve the stored non-path "Xcode (project unknown)" root against the
// daemon's working directory. Each test plants, at the working directory, a
// repository of that name that a relative resolution would find.

// TestProjectMatcherNeverReadsANonPathRoot: the repository at the working
// directory carries the remote the org's mapping lists, so a matcher that
// read it would match project X; it matches nothing and records nothing.
func TestProjectMatcherNeverReadsANonPathRoot(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	bundle, repo := writeProjectAudienceFixture(t)
	cwd := t.TempDir()
	if err := os.Rename(repo, filepath.Join(cwd, xcodehost.ProjectUnknown)); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)
	m := projectMatcher{bundlePath: bundle, now: time.Now}
	rec, ok, err := m.matchAndRecord(context.Background(), xcodehost.ProjectUnknown)
	if err != nil || ok || len(rec.OrgProjectIDs) > 0 {
		t.Errorf("matchAndRecord(%q) = %+v, %v, %v; want no match", xcodehost.ProjectUnknown, rec, ok, err)
	}
	if _, ok, _ := m.match(context.Background(), xcodehost.ProjectUnknown, nil); ok {
		t.Errorf("match(%q) matched the working directory's repository", xcodehost.ProjectUnknown)
	}
	entries, _ := os.ReadDir(filepath.Dir(projectmatch.LayoutFor(bundle).MatchPath("x")))
	if len(entries) > 0 {
		t.Errorf("a match record was written for a non-path root: %d file(s)", len(entries))
	}
}

// TestDeliveryCheckNowNeverRunsInANonPathRoot: "Check now" on the project
// whose stored root is not a path refuses before any git runs.
func TestDeliveryCheckNowNeverRunsInANonPathRoot(t *testing.T) {
	nonPathRootCwdW14(t)
	st := store.New(openDeliveryTestDB(t))
	id, err := st.UpsertProject(context.Background(), "/Users/lume/Library/Autosave Information", "")
	if err != nil {
		t.Fatal(err)
	}
	if root, _ := st.ProjectRootByID(context.Background(), id); root != xcodehost.ProjectUnknown {
		t.Fatalf("stored root = %q, want %q", root, xcodehost.ProjectUnknown)
	}
	f := deliveryReevaluateFunc(st, config.Config{Delivery: config.DeliveryConfig{Local: true}}, nil)
	if err := f(context.Background(), id); err == nil || !strings.Contains(err.Error(), "is not a path") {
		t.Errorf("Check now = %v, want the no-folder refusal", err)
	}
}

// TestGuidanceNeverStatsANonPathRoot: the scanner's existence test answers
// no for the non-path root although a folder of that name sits at the
// working directory.
func TestGuidanceNeverStatsANonPathRoot(t *testing.T) {
	nonPathRootCwdW14(t)
	if guidanceRootExists(xcodehost.ProjectUnknown) {
		t.Errorf("guidanceRootExists(%q) stat'ed the working directory's folder", xcodehost.ProjectUnknown)
	}
	if !guidanceRootExists(t.TempDir()) {
		t.Error("an absolute directory no longer exists for the scanner")
	}
}

// nonPathRootCwdW14 is nonPathRootCwd (projectroot_nonpath_test.go, built
// only with code intelligence) for these tests: a working directory holding
// a git repository named after the non-path root.
func nonPathRootCwdW14(t *testing.T) string {
	t.Helper()
	cwd := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cwd, xcodehost.ProjectUnknown, ".git", "worktrees"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)
	return cwd
}
