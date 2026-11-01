package workspace

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestBareReturnPlan(t *testing.T) {
	t.Parallel()
	repo, err := ReturnRepoPath("/home/dev/.observer/workspaces", "RUN1abcdefgh")
	if err != nil || repo != "/home/dev/.observer/workspaces/RUN1abcdefgh.return.git" {
		t.Fatalf("%q %v", repo, err)
	}
	for _, bad := range [][2]string{{"rel", "RUN1abcdefgh"}, {"/m", "../x"}, {"/m", ""}} {
		if _, err := ReturnRepoPath(bad[0], bad[1]); err == nil {
			t.Errorf("ReturnRepoPath%v accepted", bad)
		}
	}
	p, err := PlanReturn(ReturnRequest{SourceRepo: repo, CopyDir: "/home/dev/.observer/workspaces/RUN1abcdefgh/r", ManagedRoot: "/home/dev/.observer/workspaces", RunID: "RUN1abcdefgh", Bare: true, BaseCommit: strings.Repeat("a", 40)})
	if err != nil {
		t.Fatal(err)
	}
	init := p.InitBare().Argv
	if !slices.Contains(init, "--bare") || !slices.Contains(init, "--template=") || init[len(init)-1] != repo || !slices.Contains(init, "core.hooksPath=/dev/null") {
		t.Fatalf("init %v", init)
	}
	head := p.CopyHead().Argv
	if slices.Contains(head, "-C") || head[len(head)-2] != "/home/dev/.observer/workspaces/RUN1abcdefgh/r" {
		t.Fatalf("copy head %v", head)
	}
	if got := ReturnFetchCommand(repo, "refs/observer/sandbox/RUN1abcdefgh"); got != "git fetch "+repo+" refs/observer/sandbox/RUN1abcdefgh:refs/observer/sandbox/RUN1abcdefgh" {
		t.Fatal(got)
	}
	for _, step := range []Step{p.Fetch(strings.Repeat("b", 40)), p.CreateRef(strings.Repeat("b", 40))} {
		if slices.Contains(step.Argv, "push") {
			t.Fatalf("a return step pushes: %v", step.Argv)
		}
	}
}

// TestDecideReturnRepo (lane LEFT-SBX): one case per row of the return
// repository's removal table.
func TestDecideReturnRepo(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	cases := []struct {
		name   string
		f      ReturnRepoFacts
		ret    time.Duration
		remove bool
	}{
		{"live run, old and empty", ReturnRepoFacts{RunLive: true, LastWrite: now.Add(-90 * day)}, 30 * day, false},
		{"nothing returned", ReturnRepoFacts{LastWrite: now}, 30 * day, true},
		{"returned, fresh", ReturnRepoFacts{HasRef: true, LastWrite: now.Add(-2 * day)}, 30 * day, false},
		{"returned, past retention", ReturnRepoFacts{HasRef: true, LastWrite: now.Add(-31 * day)}, 30 * day, true},
		{"returned, no retention bound", ReturnRepoFacts{HasRef: true, LastWrite: now.Add(-400 * day)}, 0, false},
	}
	for _, c := range cases {
		if got, why := DecideReturnRepo(c.f, now, c.ret); got != c.remove || why == "" {
			t.Errorf("%s: remove %v (%s), want %v", c.name, got, why, c.remove)
		}
	}
}
