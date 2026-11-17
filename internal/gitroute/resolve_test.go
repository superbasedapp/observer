package gitroute

import (
	"reflect"
	"testing"
)

func TestCandidates(t *testing.T) {
	mounts := ParseMountinfo([]byte(liveMountinfo))
	path := "/home/dev/.observer/shims:/usr/local/bin:/usr/bin:/mnt/c/Program Files/Git/mingw64/bin:/mnt/c/Users/dev/scoop/shims:relative:/mnt/c/Program Files/Git/cmd/:/mnt/d/tmpfs/bin"
	got := Candidates(path, mounts)
	want := []string{
		// The interop PATH's Windows half, in order; the Linux PATH, a
		// relative entry and a non-DrvFs mount inside a drive are skipped.
		"/mnt/c/Program Files/Git/mingw64/bin/git.exe",
		"/mnt/c/Users/dev/scoop/shims/git.exe",
		"/mnt/c/Program Files/Git/cmd/git.exe",
		// Then the fixed install directories on C:, without repeats.
		"/mnt/c/Program Files (x86)/Git/cmd/git.exe",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Candidates =\n%q\nwant\n%q", got, want)
	}
}

func TestCandidatesWithoutAMountTable(t *testing.T) {
	got := Candidates("/usr/bin:/mnt/d/tools/git/cmd", nil)
	want := []string{
		"/mnt/d/tools/git/cmd/git.exe",
		"/mnt/c/Program Files/Git/cmd/git.exe",
		"/mnt/c/Program Files/Git/mingw64/bin/git.exe",
		"/mnt/c/Program Files (x86)/Git/cmd/git.exe",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Candidates =\n%q\nwant\n%q", got, want)
	}
}

func TestCandidatesWithoutADriveC(t *testing.T) {
	mounts := []Mount{{Point: "/", Root: "/", FSType: "ext4"}, {Point: "/mnt/d", Root: "/", FSType: "9p", DrvFs: true, Drive: 'D'}}
	if got := Candidates("/usr/bin", mounts); len(got) != 0 {
		t.Fatalf("Candidates = %q, want none (no C: drive mounted, no Windows PATH)", got)
	}
}

func TestIsWindowsGitVersion(t *testing.T) {
	for out, want := range map[string]bool{
		"git version 2.53.0.windows.2\n":           true,
		"  git version 2.47.1.windows.1  ":         true,
		"git version 2.53.0\n":                     false,
		"git version 2.39.5 (Apple Git-154)\n":     false,
		"":                                         false,
		"Observer shim\ngit version 2.1.windows.1": false,
	} {
		if got := IsWindowsGitVersion(out); got != want {
			t.Errorf("IsWindowsGitVersion(%q) = %v, want %v", out, got, want)
		}
	}
}
