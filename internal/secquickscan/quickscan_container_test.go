package secquickscan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/gitview"
)

// TestQuickScanDockerfileRules (OS-1): a staged Dockerfile is checked whole
// from the index; its hits ride beside a clean verdict, end of life is
// judged at the engine's clock, and a form the scan cannot read counts the
// Dockerfile unchecked.
func TestQuickScanDockerfileRules(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	git("config", "user.email", "t@example.invalid")
	git("config", "user.name", "t")
	if err := os.MkdirAll(filepath.Join(dir, "svc"), 0o700); err != nil {
		t.Fatal(err)
	}
	df := "FROM debian:buster\nRUN apt-get install -y curl\n"
	if err := os.WriteFile(filepath.Join(dir, "svc", "Dockerfile"), []byte(df), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	// The engine clock bounds the scan, so it stays real; debian buster
	// ended in 2024, so S-752 holds at any real date.
	e := &Engine{Git: gitview.RunReadOnlyTimeout}
	r := e.Scan(context.Background(), Request{Root: dir})
	if r.Verdict != VerdictClean || r.ContainerUnchecked != 0 {
		t.Fatalf("staged = %+v", r)
	}
	got := map[string]int{}
	for _, c := range r.Container {
		if c.Path != "svc/Dockerfile" || c.Message == "" {
			t.Fatalf("finding %+v", c)
		}
		got[c.RuleID] = c.Line
	}
	if got["S-751"] != 1 || got["S-752"] != 1 || got["S-753"] != 2 || len(got) != 3 {
		t.Fatalf("container hits %+v", r.Container)
	}
	if len(r.ContainerChecked) != 1 || r.ContainerChecked[0] != "svc/Dockerfile" {
		t.Fatalf("checked %+v", r.ContainerChecked)
	}
	if r := e.Scan(context.Background(), Request{Root: dir, Form: Form{All: true}}); r.ContainerUnchecked != 1 || len(r.Container) != 0 {
		t.Fatalf("-a without a working-tree reader = %+v", r)
	}
}
