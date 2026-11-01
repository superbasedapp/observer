package invariant

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestReleaseCheckMigrationsNamesAToolFailure pins T-984: when the
// released-step check cannot run, scripts/release.sh check-migrations says
// so (a TOOL failure, the rule NOT checked) instead of claiming a migration
// step breaks the released-step rule. Two causes are driven for real: go
// missing from PATH (the case seen with PATH lacking /usr/local/go/bin) and
// the checker itself erroring (a ref that names no commit).
func TestReleaseCheckMigrationsNamesAToolFailure(t *testing.T) {
	root := repoRoot(t)
	skipInPublicTree(t, root, "scripts/release.sh")
	if runtime.GOOS == "windows" {
		t.Skip("release.sh runs on a POSIX host")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH")
	}
	script := filepath.Join(root, "scripts", "release.sh")

	run := func(t *testing.T, path string, args ...string) string {
		t.Helper()
		cmd := exec.Command("bash", append([]string{script, "check-migrations"}, args...)...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "PATH="+path)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("check-migrations %v succeeded, want a failure:\n%s", args, out)
		}
		return string(out)
	}
	assertToolFailure := func(t *testing.T, out, cause string) {
		t.Helper()
		if !strings.Contains(out, "TOOL FAILURE") || !strings.Contains(out, "NOT checked") || !strings.Contains(out, cause) {
			t.Errorf("output does not name the tool failure (%q):\n%s", cause, out)
		}
		if strings.Contains(out, "breaks the released-step rule") {
			t.Errorf("a tool failure was reported as a released-step rule violation:\n%s", out)
		}
	}

	t.Run("go missing from PATH", func(t *testing.T) {
		path := pathWithoutGo(t)
		assertToolFailure(t, run(t, path, "HEAD"), "go is not on PATH")
	})
	t.Run("checker errors", func(t *testing.T) {
		if _, err := exec.LookPath("go"); err != nil {
			t.Skip("go not on PATH")
		}
		assertToolFailure(t, run(t, os.Getenv("PATH"), "refs/heads/no-such-branch-t984"), "shippedmiggen exited 1")
	})
}

// pathWithoutGo returns the current PATH with every directory that holds a
// `go` executable removed, skipping the test when bash or git would go with
// it.
func pathWithoutGo(t *testing.T) string {
	t.Helper()
	var keep []string
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		if info, err := os.Stat(filepath.Join(dir, "go")); err == nil && !info.IsDir() {
			continue
		}
		keep = append(keep, dir)
	}
	path := strings.Join(keep, string(os.PathListSeparator))
	for _, tool := range []string{"bash", "git"} {
		found := false
		for _, dir := range keep {
			if info, err := os.Stat(filepath.Join(dir, tool)); err == nil && !info.IsDir() {
				found = true
				break
			}
		}
		if !found {
			t.Skipf("%s shares a PATH directory with go; cannot build a PATH without go", tool)
		}
	}
	return path
}
