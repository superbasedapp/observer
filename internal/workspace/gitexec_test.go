package workspace

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// writeGitDir builds a minimal git dir on disk: HEAD, objects/info, refs and
// info so a real git dir's shape (and the placeholder-landing shape) holds,
// plus a clean config and one .sample hook, like a fresh clone.
func writeGitDir(t *testing.T, dir string) {
	t.Helper()
	for _, d := range []string{"objects/info", "objects/pack", "refs/heads", "info", "hooks"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(dir, "HEAD"), "ref: refs/heads/main\n")
	write(t, filepath.Join(dir, "config"), "[core]\n\trepositoryformatversion = 0\n")
	write(t, filepath.Join(dir, "hooks", "pre-commit.sample"), "#!/bin/sh\nexit 0\n")
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestScanGitDirExecRiskFindsPlantedPaths: the scan reports every planted
// execution-risk path, including the ones inside a linked-worktree git dir
// and a submodule git dir, and never a .sample hook.
func TestScanGitDirExecRiskFindsPlantedPaths(t *testing.T) {
	gd := filepath.Join(t.TempDir(), ".git")
	writeGitDir(t, gd)
	write(t, filepath.Join(gd, "commondir"), "../evil\n")
	write(t, filepath.Join(gd, "config.worktree"), "[alias]\n\tx = !sh\n")
	write(t, filepath.Join(gd, "info", "attributes"), "* filter=evil\n")
	write(t, filepath.Join(gd, "objects", "info", "alternates"), "/tmp/odb\n")
	write(t, filepath.Join(gd, "hooks", "post-commit"), "#!/bin/sh\ntouch /tmp/x\n")
	// A linked worktree git dir.
	wt := filepath.Join(gd, "worktrees", "wt1")
	writeGitDir(t, wt)
	write(t, filepath.Join(wt, "commondir"), "../..\n")
	write(t, filepath.Join(wt, "config.worktree"), "[alias]\n\ty = !sh\n")
	// A submodule git dir.
	sub := filepath.Join(gd, "modules", "sub")
	writeGitDir(t, sub)
	write(t, filepath.Join(sub, "hooks", "post-checkout"), "#!/bin/sh\n")

	got, err := ScanGitDirExecRisk(gd)
	if err != nil {
		t.Fatal(err)
	}
	wantKeys := []string{
		"config",
		"commondir",
		"config.worktree",
		"info/attributes",
		"objects/info/alternates",
		"hooks/post-commit",
		"worktrees/wt1/commondir",
		"worktrees/wt1/config.worktree",
		"worktrees/wt1/config",
		"modules/sub/config",
		"modules/sub/hooks/post-checkout",
	}
	for _, k := range wantKeys {
		if _, ok := got[k]; !ok {
			t.Errorf("ScanGitDirExecRisk missing key %q (got %v)", k, keys(got))
		}
	}
	if _, ok := got["hooks/pre-commit.sample"]; ok {
		t.Error("a .sample hook must not be reported")
	}
}

// TestCopyReturnGitDirViolationsCleanAndPlanted: a clean clone's git dir has
// no violation; a box-planted one is refused, naming each path, before any
// host git touches it.
func TestCopyReturnGitDirViolationsCleanAndPlanted(t *testing.T) {
	clean := filepath.Join(t.TempDir(), ".git")
	writeGitDir(t, clean)
	viol, err := CopyReturnGitDirViolations(clean)
	if err != nil {
		t.Fatal(err)
	}
	if len(viol) != 0 {
		t.Fatalf("a clean clone has violations: %v", viol)
	}

	planted := filepath.Join(t.TempDir(), ".git")
	writeGitDir(t, planted)
	write(t, filepath.Join(planted, "commondir"), "../evil\n")
	write(t, filepath.Join(planted, "config.worktree"), "[core]\n")
	write(t, filepath.Join(planted, "objects", "info", "alternates"), "/tmp/odb\n")
	write(t, filepath.Join(planted, "hooks", "post-commit"), "#!/bin/sh\n")
	write(t, filepath.Join(planted, "config"), "[uploadpack]\n\tpackObjectsHook = touch /tmp/x\n")
	viol, err = CopyReturnGitDirViolations(planted)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"commondir", "config.worktree", "objects/info/alternates", "hooks/post-commit"} {
		if !slices.Contains(viol, want) {
			t.Errorf("violations %v lack %q", viol, want)
		}
	}
	hasConfigKey := false
	for _, v := range viol {
		if len(v) >= 6 && v[:6] == "config" && v != "config" {
			hasConfigKey = true
		}
	}
	if !hasConfigKey {
		t.Errorf("violations %v do not flag the uploadpack hook in config", viol)
	}
}

// TestGitDirExecRiskChanged: a new or changed path is reported, a removed one
// is not (removal is not an execution risk).
func TestGitDirExecRiskChanged(t *testing.T) {
	before := map[string]string{"config": "a", "hooks/x": "h"}
	after := map[string]string{"config": "b", "commondir": "c"}
	got := GitDirExecRiskChanged(before, after)
	want := []string{"commondir", "config"}
	if !slices.Equal(got, want) {
		t.Fatalf("changed = %v, want %v", got, want)
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
