package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
)

// Lane sec-p2a merge fixes on the node: the failed-resolve backoff below the
// cap (audit finding 4), the root-commit read through the read-only git
// envelope (finding 6) and the guard status line for the org's
// project_unknown value.

// TestProjectMatcherBacksOffAFailedResolveBelowTheCap: a failed resolve below
// the cap is remembered (an unmatched resolve record, never unknown), so the
// loop and the next launch do not ask again until it expires, and each
// further failure doubles the wait up to the cap.
func TestProjectMatcherBacksOffAFailedResolveBelowTheCap(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ctx := context.Background()
	bundle, dir, priv := writeAboveCapFixture(t, false)
	f := &fakeResolve{priv: priv, fail: errors.New("offline")}
	clock := time.Now()
	m := projectMatcher{bundlePath: bundle, now: func() time.Time { return clock }, resolve: f.call}
	rec, _, err := m.matchAndRecord(ctx, dir)
	if err != nil || rec.Unknown || len(rec.OrgProjectIDs) != 0 || rec.Source != projectmatch.SourceResolve || rec.Reason != projectResolveFailedBelowCap {
		t.Fatalf("failed resolve below the cap = %+v (%v)", rec, err)
	}
	if span := rec.ValidUntil.Sub(rec.MatchedAt); span != projectResolveUnknownRetry {
		t.Fatalf("first backoff %s, want %s", span, projectResolveUnknownRetry)
	}
	clock = clock.Add(30 * time.Second)
	if _, _, err := m.matchAndRecord(ctx, dir); err != nil || f.calls != 1 {
		t.Fatalf("the loop asked again inside the backoff: %d calls (%v)", f.calls, err)
	}
	clock = rec.ValidUntil.Add(time.Second)
	rec2, _, err := m.matchAndRecord(ctx, dir)
	if err != nil || f.calls != 2 {
		t.Fatalf("an expired backoff was not retried: %d calls (%v)", f.calls, err)
	}
	if span := rec2.ValidUntil.Sub(rec2.MatchedAt); span != 2*projectResolveUnknownRetry {
		t.Fatalf("second backoff %s, want %s", span, 2*projectResolveUnknownRetry)
	}
	if d := projectResolveBackoff(&projectmatch.MatchFile{
		Source: projectmatch.SourceResolve, Reason: projectResolveFailedBelowCap, BundleVersion: 9,
		MatchedAt: clock, ValidUntil: clock.Add(5 * time.Hour),
	}, 9); d != projectResolveBackoffMax {
		t.Fatalf("backoff past the cap = %s, want %s", d, projectResolveBackoffMax)
	}
	// The guard reads the remembered record as unmatched, not unknown.
	composed, ok := composedProjectBundle(bundle)
	if !ok {
		t.Fatal("no v3 bundle")
	}
	dec := projectmatch.Decide(projectmatch.DecideInput{
		Composed: composed.ProjectBinding, ComposedVersion: composed.Version, Record: &rec2, Now: clock,
	})
	if dec.State != projectmatch.StateUnmatched {
		t.Fatalf("the backoff record decides %+v, want unmatched", dec)
	}
}

// TestProjectRootCommitRunsInTheReadOnlyEnvelope: the launch-time root-commit
// read returns git.DefaultRootCommit's answer, and the envelope it runs in
// applies the git hardening environment (no global config reaches it).
func TestProjectRootCommitRunsInTheReadOnlyEnvelope(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ctx := context.Background()
	home := t.TempDir()
	writeFileT(t, filepath.Join(home, ".gitconfig"), "[user]\n\tname = leaked-global\n")
	setTestHome(t, home)
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(home, ".gitconfig"))
	dir := t.TempDir()
	for _, args := range [][]string{{"init", "-q"}, {"commit", "-q", "--allow-empty", "-m", "root"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	want, err := git.DefaultRootCommit(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := projectRootCommit(ctx, dir); err != nil || got != want {
		t.Fatalf("projectRootCommit = %q (%v), want %q", got, err, want)
	}
	if _, err := projectRootCommit(ctx, t.TempDir()); err == nil {
		t.Fatal("a directory with no repository returned a root commit")
	}
	// The envelope without the hardening environment still reads the global
	// config; with it (what projectRootCommit passes) nothing global does.
	if out, _, err := gitview.RunReadOnlyTimeout(ctx, dir, 0, 0, "config", "user.name"); err != nil || strings.TrimSpace(string(out)) != "leaked-global" {
		t.Fatalf("control read = %q (%v), want the global value", out, err)
	}
	if !gitAtLeast(t, 2, 32) {
		// GIT_CONFIG_GLOBAL (the hardening environment's global-config
		// switch) arrived in git 2.32; an older git reads ~/.gitconfig
		// regardless, so this half needs a newer host git.
		t.Log("skipped the global-config half: host git is older than 2.32")
		return
	}
	if out, _, _ := gitview.RunReadOnlyEnv(ctx, dir, 0, 0, extrun.GitHardeningEnv(runtime.GOOS), "config", "user.name"); strings.TrimSpace(string(out)) != "" {
		t.Fatalf("the hardened envelope read the global config: %q", out)
	}
}

// gitAtLeast reports whether the host git is at least major.minor.
func gitAtLeast(t *testing.T, major, minor int) bool {
	t.Helper()
	out, err := exec.Command("git", "version").Output()
	if err != nil {
		return false
	}
	var ma, mi int
	fields := strings.Fields(string(out))
	if len(fields) < 3 {
		return false
	}
	if _, err := fmt.Sscanf(fields[2], "%d.%d", &ma, &mi); err != nil {
		return false
	}
	return ma > major || (ma == major && mi >= minor)
}

// TestGuardStatusShowsTheProjectUnknownValue: `observer guard status` prints
// the org's project_unknown value while the org bundle carries the project
// audience, and prints nothing for a bundle that does not.
func TestGuardStatusShowsTheProjectUnknownValue(t *testing.T) {
	cp := projectHookNode(t, "# floor\n[project_audience]\nunknown = \"ask\"\n", "https://github.com/acme/widget.git", time.Now())
	out, err := runGuardCmd(t, "status", "--config", cp)
	if err != nil {
		t.Fatalf("guard status: %v\n%s", err, out)
	}
	if !strings.Contains(out, `Project floor: project_unknown = "ask"`) {
		t.Fatalf("guard status does not show the org's project_unknown:\n%s", out)
	}
	n := newOrgLockNode(t, false)
	out, _ = runGuardCmd(t, "status", "--config", n.cfgPath)
	if strings.Contains(out, "Project floor:") {
		t.Fatalf("a bundle with no project audience printed a project floor:\n%s", out)
	}
}
