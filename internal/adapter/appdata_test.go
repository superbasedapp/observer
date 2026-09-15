package adapter

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// TestAppDataRootsIsOSShaped is the table for the OS-shape half of
// ticket "Crossmount root hygiene 2026-09-03". The load-bearing rows
// are the FOREIGN Windows homes a WSL2 daemon reaches over /mnt/c:
// they must yield the Windows shape only, never
// "Library/Application Support" and never ".config" — those paths
// cannot exist under a Windows profile, yet the daemon was composing,
// registering and logging them for every profile on the box.
func TestAppDataRootsIsOSShaped(t *testing.T) {
	t.Parallel()

	// allShapes is the maximal declaration: a tool that (claims to)
	// use every convention. Even so, each home gets only its own.
	allShapes := AppDataSpec{
		Name: "com.example.app",
		Shapes: ShapeWindowsRoaming | ShapeWindowsLocal |
			ShapeDarwinAppSupport | ShapeXDGConfig,
	}
	winOnly := AppDataSpec{Name: "Grok Bot", Shapes: ShapeWindowsRoaming}
	xdgEverywhere := AppDataSpec{
		Name:         "kilo",
		Shapes:       ShapeWindowsRoaming | ShapeDarwinAppSupport | ShapeXDGConfig,
		XDGOnWindows: true,
	}

	// foreignWin is a Windows profile as a WSL2 daemon sees it. The
	// path is spelled with filepath.Join so the test runs on a Windows
	// host too.
	foreignWin := crossmount.HomeRoot{
		Path:   filepath.Join("/mnt/c/Users", "auzy_"),
		OS:     crossmount.OSWindows,
		Origin: "wsl-mnt:auzy_",
	}
	nativeLinux := crossmount.HomeRoot{
		Path: filepath.Join("/home", "me"), OS: crossmount.OSLinux, Origin: "native",
	}
	nativeDarwin := crossmount.HomeRoot{
		Path: filepath.Join("/Users", "me"), OS: crossmount.OSDarwin, Origin: "native",
	}
	foreignLinux := crossmount.HomeRoot{
		Path:   filepath.Join(`\\wsl.localhost\`, "Ubuntu", "home", "me"),
		OS:     crossmount.OSLinux,
		Origin: "wslhost:Ubuntu/me",
	}

	tests := []struct {
		name string
		home crossmount.HomeRoot
		spec AppDataSpec
		want []string
		why  string
	}{
		{
			name: "foreign windows home gets windows shapes only",
			home: foreignWin, spec: allShapes,
			want: []string{
				filepath.Join(foreignWin.Path, "AppData", "Roaming", "com.example.app"),
				filepath.Join(foreignWin.Path, "AppData", "Local", "com.example.app"),
			},
			why: "the live regression: no Application Support, no .config under /mnt/c",
		},
		{
			name: "foreign windows home, roaming-only spec",
			home: foreignWin, spec: winOnly,
			want: []string{filepath.Join(foreignWin.Path, "AppData", "Roaming", "Grok Bot")},
			why:  "an undeclared shape is never invented",
		},
		{
			name: "native linux home gets XDG only",
			home: nativeLinux, spec: allShapes,
			want: []string{filepath.Join(nativeLinux.Path, ".config", "com.example.app")},
			why:  "unchanged from before the ticket",
		},
		{
			name: "darwin home gets Application Support only",
			home: nativeDarwin, spec: allShapes,
			want: []string{
				filepath.Join(nativeDarwin.Path, "Library", "Application Support", "com.example.app"),
			},
			why: "unchanged from before the ticket",
		},
		{
			name: "foreign linux home over wsl.localhost gets XDG",
			home: foreignLinux, spec: allShapes,
			want: []string{filepath.Join(foreignLinux.Path, ".config", "com.example.app")},
			why:  "the Windows-host direction of the bridge is symmetric",
		},
		{
			name: "XDGOnWindows opt-in adds .config under a windows home",
			home: foreignWin, spec: xdgEverywhere,
			want: []string{
				filepath.Join(foreignWin.Path, "AppData", "Roaming", "kilo"),
				filepath.Join(foreignWin.Path, ".config", "kilo"),
			},
			why: "the honest exception: a tool that mirrors XDG everywhere",
		},
		{
			name: "XDGOnWindows does not change a linux home",
			home: nativeLinux, spec: xdgEverywhere,
			want: []string{filepath.Join(nativeLinux.Path, ".config", "kilo")},
			why:  "the flag only widens the Windows branch",
		},
		{
			name: "empty home yields nothing",
			home: crossmount.HomeRoot{OS: crossmount.OSWindows}, spec: allShapes,
			want: nil,
			why:  "a home with no path is not a home",
		},
		{
			name: "empty name yields nothing",
			home: foreignWin, spec: AppDataSpec{Shapes: ShapeWindowsRoaming},
			want: nil,
			why:  "there is no directory to name",
		},
		{
			name: "no shapes declared yields nothing",
			home: foreignWin, spec: AppDataSpec{Name: "x"},
			want: nil,
			why:  "the zero value is 'no grounded shape', never a guess",
		},
		{
			name: "unknown home OS yields nothing",
			home: crossmount.HomeRoot{Path: "/somewhere", OS: "plan9"}, spec: allShapes,
			want: nil,
			why:  "same contract as vscodehost.UserDir",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := AppDataRoots(tc.home, tc.spec)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("%s\n got: %#v\nwant: %#v", tc.why, got, tc.want)
			}
		})
	}
}

// TestAppDataRootsNeverConsultsEnvForAForeignHome pins the reason
// nativeWindowsEnvDir is gated on Origin: the running process's
// %APPDATA% describes ITS OWN profile, so applying it to a home reached
// over /mnt/c would point one user's watch root at another user's
// directory.
func TestAppDataRootsNeverConsultsEnvForAForeignHome(t *testing.T) {
	// No t.Parallel: t.Setenv mutates process state.
	t.Setenv("APPDATA", filepath.Join("D:", "Roaming"))
	t.Setenv("LOCALAPPDATA", filepath.Join("D:", "Local"))

	foreign := crossmount.HomeRoot{
		Path:   filepath.Join("/mnt/c/Users", "someone-else"),
		OS:     crossmount.OSWindows,
		Origin: "wsl-mnt:someone-else",
	}
	got := AppDataRoots(foreign, AppDataSpec{
		Name:   "app",
		Shapes: ShapeWindowsRoaming | ShapeWindowsLocal,
	})
	want := []string{
		filepath.Join(foreign.Path, "AppData", "Roaming", "app"),
		filepath.Join(foreign.Path, "AppData", "Local", "app"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v want %#v", got, want)
	}
}
