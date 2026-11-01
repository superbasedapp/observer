package policy

import (
	"reflect"
	"testing"
)

// TestGitWriteLocations: one row per way a line can place its gating write
// (lane SEC-GATE5 milestone 1). The event runs in /repo.
func TestGitWriteLocations(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		dialect Dialect
		want    [][]string // per gating write, its Dirs
		unknown []bool     // per gating write
	}{
		{"plain commit", "git commit -m x", DialectPosix, [][]string{{"/repo"}}, []bool{false}},
		{"plain push", "git push", DialectPosix, [][]string{{"/repo"}}, []bool{false}},
		{"cd to another repository", "cd /other && git commit -m x", DialectPosix, [][]string{{"/other"}}, []bool{false}},
		{"cd after the commit", "git commit -m x && cd /other", DialectPosix, [][]string{{"/repo"}}, []bool{false}},
		{"cd then semicolon keeps both", "cd /other; git commit -m x", DialectPosix, [][]string{{"/other", "/repo"}}, []bool{false}},
		{"subshell", "(cd /other && git commit -m x)", DialectPosix, [][]string{{"/other"}}, []bool{false}},
		{"subshell restores", "(cd /other) && git commit -m x", DialectPosix, [][]string{{"/repo"}}, []bool{false}},
		{"pushd", "pushd /other && git commit -m x && popd", DialectPosix, [][]string{{"/other"}}, []bool{false}},
		{"dash C", "git -C /other commit -m x", DialectPosix, [][]string{{"/other"}}, []bool{false}},
		{"dash C relative after cd", "cd /a && git -C b commit -m x", DialectPosix, [][]string{{"/a/b"}}, []bool{false}},
		{"two dash C", "git -C /a -C b commit -m x", DialectPosix, [][]string{{"/a/b"}}, []bool{false}},
		{"git dir option", "git --git-dir=/other/.git commit -m x", DialectPosix, [][]string{{"/other/.git"}}, []bool{false}},
		{"git dir and work tree", "git --git-dir /o/.git --work-tree /o commit -m x", DialectPosix, [][]string{{"/o/.git", "/o"}}, []bool{false}},
		{"GIT_DIR prefix", "GIT_DIR=/other/.git git commit -m x", DialectPosix, [][]string{{"/other/.git"}}, []bool{false}},
		{"GIT_DIR exported", "export GIT_DIR=/other/.git; git commit -m x", DialectPosix, [][]string{{"/other/.git"}}, []bool{false}},
		{"GIT_WORK_TREE keeps the cwd", "GIT_WORK_TREE=/o git commit -m x", DialectPosix, [][]string{{"/repo", "/o"}}, []bool{false}},
		{"nested shell", "bash -c 'cd /other && git commit -m x'", DialectPosix, [][]string{{"/other"}}, []bool{false}},
		{"PowerShell Set-Location", "Set-Location C:\\work\\elsewhere; git commit -m x", DialectPowerShell, [][]string{{"c:/work/elsewhere", "/repo"}}, []bool{false}},
		{"unresolved cd", "cd $REPO && git commit -m x", DialectPosix, [][]string{nil}, []bool{true}},
		{"cd dash", "cd - && git commit -m x", DialectPosix, [][]string{nil}, []bool{true}},
		{"dash C with a variable", "git -C \"$D\" commit -m x", DialectPosix, [][]string{nil}, []bool{true}},
		{"GIT_DIR with a variable", "GIT_DIR=$X git commit -m x", DialectPosix, [][]string{nil}, []bool{true}},
		{"two writes, two repositories", "git commit -m a && cd /other && git commit -m b", DialectPosix, [][]string{{"/repo"}, {"/other"}}, []bool{false, false}},
		{"no write", "cd /other && ls", DialectPosix, nil, nil},
	}
	for _, tc := range cases {
		ev := &Event{Kind: KindShellExec, Target: tc.line, Cwd: "/repo", Dialect: tc.dialect}
		got := GitWriteLocations(&MatchContext{Event: ev, Cfg: &Config{Home: "/home/u"}})
		if len(got) != len(tc.want) {
			t.Fatalf("%s: %d writes %+v, want %d", tc.name, len(got), got, len(tc.want))
		}
		for i, loc := range got {
			if !reflect.DeepEqual(loc.Dirs, tc.want[i]) || loc.Unknown != tc.unknown[i] {
				t.Errorf("%s: write %d = dirs %q unknown %v (%s), want %q unknown %v", tc.name, i, loc.Dirs, loc.Unknown, loc.UnknownVia, tc.want[i], tc.unknown[i])
			}
		}
	}
}

// TestGitWriteLocationsNoAnchor: an event with no working directory and
// no project root cannot place a relative write.
func TestGitWriteLocationsNoAnchor(t *testing.T) {
	ev := &Event{Kind: KindShellExec, Target: "git commit -m x"}
	got := GitWriteLocations(&MatchContext{Event: ev, Cfg: &Config{}})
	if len(got) != 1 || !got[0].Unknown {
		t.Fatalf("locations %+v, want one unknown write", got)
	}
	ev = &Event{Kind: KindShellExec, Target: "git -C /abs commit -m x"}
	got = GitWriteLocations(&MatchContext{Event: ev, Cfg: &Config{}})
	if len(got) != 1 || got[0].Unknown || !reflect.DeepEqual(got[0].Dirs, []string{"/abs"}) {
		t.Fatalf("absolute -C with no anchor: %+v", got)
	}
}

// TestGitDirWorkTree maps a work tree's own .git to the work tree only.
func TestGitDirWorkTree(t *testing.T) {
	for in, want := range map[string]string{
		"/o/.git":              "/o",
		"/o":                   "/o",
		"/srv/bare.git":        "/srv/bare.git",
		"/o/.git/worktrees/wt": "/o/.git/worktrees/wt",
		`C:\Users\u\proj\.git`: "c:/Users/u/proj",
	} {
		if got := GitDirWorkTree(in); got != want {
			t.Errorf("GitDirWorkTree(%q) = %q, want %q", in, got, want)
		}
	}
}
