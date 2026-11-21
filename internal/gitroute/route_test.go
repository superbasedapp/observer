package gitroute

import (
	"reflect"
	"testing"
)

// TestChoose walks the route table, one case per row and per edge.
func TestChoose(t *testing.T) {
	mounts := ParseMountinfo([]byte(liveMountinfo))
	onD, _ := MountFor(mounts, "/mnt/d/repo")
	onExt4, _ := MountFor(mounts, "/home/dev/repo")
	const gitExe = "/mnt/c/Program Files/Git/cmd/git.exe"
	diff := []string{"diff", "--no-color", "-U0", "HEAD"}
	wsl := func(m Mount, interop bool, git string) Facts {
		return Facts{GOOS: "linux", Mount: m, MountOK: true, Interop: interop, WindowsGit: git}
	}
	drvfs := Plan{Route: RouteDrvFsStat, ConfigArgs: DrvFsStatArgs}
	for _, tc := range []struct {
		name  string
		facts Facts
		root  string
		args  []string
		want  Plan
	}{
		{"native Windows daemon: its own git", Facts{GOOS: "windows"}, `D:\repo`, diff, Plan{Route: RouteHost}},
		{"macOS: its own git", Facts{GOOS: "darwin"}, "/mnt/d/repo", diff, Plan{Route: RouteHost}},
		{"WSL, repository on ext4: its own git", wsl(onExt4, true, gitExe), "/home/dev/repo", diff, Plan{Route: RouteHost}},
		{"WSL, no mount found: its own git", Facts{GOOS: "linux"}, "/mnt/d/repo", diff, Plan{Route: RouteHost}},
		{"WSL, Windows drive, interop and git.exe: git.exe", wsl(onD, true, gitExe), "/mnt/d/repo", diff, Plan{
			Route: RouteWindowsGit, Program: gitExe, Dir: `D:\repo`,
			Fallback: &Plan{Route: RouteDrvFsAfterWindows, ConfigArgs: DrvFsStatArgs},
		}},
		{"WSL, Windows drive, interop off: WSL git, minimal stat", wsl(onD, false, gitExe), "/mnt/d/repo", diff, drvfs},
		{"WSL, Windows drive, no git.exe: WSL git, minimal stat", wsl(onD, true, ""), "/mnt/d/repo", diff, drvfs},
		{"relative pathspecs stay on git.exe", wsl(onD, true, gitExe), "/mnt/d/repo", []string{"diff", "HEAD", "--", "src/a.go", "b c.txt"}, Plan{
			Route: RouteWindowsGit, Program: gitExe, Dir: `D:\repo`,
			Fallback: &Plan{Route: RouteDrvFsAfterWindows, ConfigArgs: DrvFsStatArgs},
		}},
		{"an absolute pathspec is read by the WSL git", wsl(onD, true, gitExe), "/mnt/d/repo", []string{"diff", "HEAD", "--", "/mnt/d/repo/a.go"}, drvfs},
		{"a root the drive cannot spell falls through to the WSL git", wsl(Mount{Point: "/mnt/d", DrvFs: true}, true, gitExe), "/mnt/d/repo", diff, drvfs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Choose(tc.facts, tc.root, tc.args)
			if got.Why == "" {
				t.Fatal("the plan carries no rule")
			}
			got.Why = ""
			if got.Fallback != nil {
				fb := *got.Fallback
				fb.Why = ""
				got.Fallback = &fb
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Choose =\n%+v\nwant\n%+v", got, tc.want)
			}
		})
	}
}

// TestDrvFsStatArgsAreCopied: a caller appending to a plan's ConfigArgs
// never writes into the shared table.
func TestDrvFsStatArgsAreCopied(t *testing.T) {
	p := Choose(Facts{GOOS: "linux", Mount: Mount{Point: "/mnt/d", Root: "/", DrvFs: true, Drive: 'D'}, MountOK: true}, "/mnt/d/r", nil)
	p.ConfigArgs[0] = "changed"
	if DrvFsStatArgs[0] != "-c" {
		t.Fatal("a plan's ConfigArgs alias DrvFsStatArgs")
	}
}

func TestPortableArgs(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{[]string{"diff", "--cached", "--no-color"}, true},
		{[]string{"cat-file", "blob", ":src/a.go"}, true},
		{[]string{"log", "-p", "@{upstream}..HEAD", "--"}, true},
		{[]string{"diff", "HEAD", "--", "rel/x"}, true},
		{[]string{"diff", "HEAD", "--", "/abs/x"}, false},
		{[]string{"diff", "HEAD", "--", `\\srv\x`}, false},
		// What the interop command line would re-split differently.
		{[]string{"diff", "HEAD", "--", `a" --output=C:\x "b`}, false},
		{[]string{"diff", "HEAD", "--", `dir\`}, false},
		{[]string{"diff", "HEAD", "--", "a\tb"}, false},
		{[]string{"diff", "HEAD", "--", "with space/and-dash.txt"}, true},
	} {
		if got := portableArgs(tc.args); got != tc.want {
			t.Errorf("portableArgs(%q) = %v, want %v", tc.args, got, tc.want)
		}
	}
}
