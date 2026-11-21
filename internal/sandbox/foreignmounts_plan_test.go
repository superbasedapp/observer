package sandbox

import (
	"runtime"
	"testing"
)

// skipPlannerOnWindows skips a test that renders a bwrap argv: the planner
// validates paths with the host's rules (filepath.IsAbs), so a POSIX path is
// "not absolute" on a Windows host and every sibling planner test in this
// package fails there too. The planner only ever runs on Linux.
func skipPlannerOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the bwrap planner is Linux-only: its path rules are the host's")
	}
}

// TestBuildPlanWorkspaceOnMaskedDriveStaysBound pins what the live check
// proved with a real bwrap: with every Windows drive masked, a project on
// /mnt/d is still bound read-write, because the mask is applied before the
// punch-backs and bwrap resolves each bind source against the host. The rest
// of /mnt/d, and all of /mnt/c, stay hidden behind the empty tmpfs; the
// observer binary and a tool directory that live on the drive are re-bound
// read-only the same way.
func TestBuildPlanWorkspaceOnMaskedDriveStaysBound(t *testing.T) {
	t.Parallel()
	skipPlannerOnWindows(t)
	req := canonicalReq()
	req.MaskPaths = []string{"/mnt/c", "/mnt/d"}
	req.WorkspaceRoot = "/mnt/d/programsx/proj"
	req.ObserverBin = "/mnt/d/programsx/superbased-observer/bin/observer"
	req.ToolBinDirs = []string{"/mnt/d/tools/bin"}
	plan, err := BuildPlan(req)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	argv := plan.Argv([]string{"true"})

	mask := findFlagOperand(argv, flagTmpfs, "/mnt/d")
	if mask < 0 || findFlagOperand(argv, flagTmpfs, "/mnt/c") < 0 {
		t.Fatalf("both drives must be masked: %v", argv)
	}
	ws := findFlagOperand(argv, flagBind, req.WorkspaceRoot)
	if ws < 0 {
		t.Fatalf("the workspace under the masked drive is not bound: %v", argv)
	}
	if argv[ws+2] != req.WorkspaceRoot {
		t.Errorf("the workspace is bound at %q, want itself", argv[ws+2])
	}
	if mask >= ws {
		t.Errorf("the /mnt/d mask (%d) must precede the workspace bind (%d), or the bind would be hidden", mask, ws)
	}
	for _, p := range []string{req.ObserverBin, "/mnt/d/tools/bin"} {
		i := findFlagOperand(argv, flagROBindTry, p)
		if i < 0 || i < mask {
			t.Errorf("%s: read-only bind at %d, want one after the mask at %d", p, i, mask)
		}
	}
	// Nothing re-exposes the drive as a whole: no bind of /mnt/d or /mnt/c
	// itself, in any flavour.
	for _, flag := range []string{flagBind, flagBindTry, flagROBind, flagROBindTry} {
		for _, d := range []string{"/mnt/c", "/mnt/d"} {
			if findFlagOperand(argv, flag, d) >= 0 {
				t.Errorf("%s %s re-exposes a masked drive: %v", flag, d, argv)
			}
		}
	}
}

// TestBuildPlanHomeOnMaskedDrive: a scratch HOME on a masked drive (the
// throwaway nodes of the dev box live under /mnt/d) must not lose its home
// tmpfs to the mask. The mask holding the home goes first, then the home's
// own tmpfs; a mask that does not hold it keeps its place after the home.
func TestBuildPlanHomeOnMaskedDrive(t *testing.T) {
	t.Parallel()
	skipPlannerOnWindows(t)
	req := canonicalReq()
	req.Home = "/mnt/d/scratch/home"
	req.ObserverDir = "/mnt/d/scratch/home/.observer"
	req.WorkspaceRoot = "/mnt/d/scratch/home/.observer/workspaces/abc/repo"
	req.ObserverBin = "/mnt/d/scratch/home/.local/bin/observer"
	req.ToolBinDirs = []string{"/mnt/d/scratch/home/.local/bin"}
	req.MaskPaths = []string{"/mnt/c", "/mnt/d"}
	plan, err := BuildPlan(req)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	argv := plan.Argv([]string{"true"})
	maskD := findFlagOperand(argv, flagTmpfs, "/mnt/d")
	home := findFlagOperand(argv, flagTmpfs, req.Home)
	maskC := findFlagOperand(argv, flagTmpfs, "/mnt/c")
	if maskD < 0 || home < 0 || maskC < 0 {
		t.Fatalf("missing mask or home tmpfs: %v", argv)
	}
	if !(maskD < home) {
		t.Errorf("the mask holding the home (%d) must precede the home tmpfs (%d), or it hides it", maskD, home)
	}
	if !(home < maskC) {
		t.Errorf("a mask that does not hold the home (/mnt/c at %d) keeps its place after the home tmpfs (%d)", maskC, home)
	}

	// home_mode readonly makes no home tmpfs: the masks are all applied
	// where they always were.
	req.HomeMode = "readonly"
	plan, err = BuildPlan(req)
	if err != nil {
		t.Fatalf("BuildPlan readonly: %v", err)
	}
	argv = plan.Argv([]string{"true"})
	if findFlagOperand(argv, flagTmpfs, req.Home) >= 0 {
		t.Errorf("readonly mode must not make a home tmpfs: %v", argv)
	}
	if findFlagOperand(argv, flagTmpfs, "/mnt/d") < 0 {
		t.Errorf("readonly mode still masks the drive: %v", argv)
	}
}

// TestBuildOneShotOnMaskedDrive is the same for the one-shot planner: the
// project on a masked drive is still bound (read-only), and a home on the
// drive keeps its tmpfs.
func TestBuildOneShotOnMaskedDrive(t *testing.T) {
	t.Parallel()
	skipPlannerOnWindows(t)
	req := baseOneShot()
	req.MaskPaths = []string{"/mnt/c", "/mnt/d"}
	req.ProjectRoot = "/mnt/d/src/proj"
	plan, err := BuildOneShot(req)
	if err != nil {
		t.Fatalf("BuildOneShot: %v", err)
	}
	argv := plan.Argv([]string{"true"})
	mask := findFlagOperand(argv, flagTmpfs, "/mnt/d")
	proj := findFlagOperand(argv, flagROBind, req.ProjectRoot)
	if mask < 0 || proj < 0 || mask >= proj {
		t.Fatalf("the project on /mnt/d must be bound read-only after the mask: mask %d, project %d: %v", mask, proj, argv)
	}

	req.Home = "/mnt/d/scratch/home"
	req.ObserverDir = "/mnt/d/scratch/home/.observer"
	req.CacheDir = "/mnt/d/scratch/home/.cache/engines/gosec"
	req.ProgramDirs = []string{"/opt/scanners/bin"}
	plan, err = BuildOneShot(req)
	if err != nil {
		t.Fatalf("BuildOneShot, home on the drive: %v", err)
	}
	argv = plan.Argv([]string{"true"})
	mask = findFlagOperand(argv, flagTmpfs, "/mnt/d")
	home := findFlagOperand(argv, flagTmpfs, req.Home)
	if mask < 0 || home < 0 || mask >= home {
		t.Errorf("the mask holding the home (%d) must precede the home tmpfs (%d): %v", mask, home, argv)
	}
	if c := findFlagOperand(argv, flagTmpfs, "/mnt/c"); c < home {
		t.Errorf("a mask not holding the home (/mnt/c at %d) keeps its place after the home tmpfs (%d)", c, home)
	}
}

// TestSplitMasksAboveHome pins the split: only a mask that holds the home
// moves, each side keeps its order, and a home that is no mask's descendant
// leaves the list as it was.
func TestSplitMasksAboveHome(t *testing.T) {
	t.Parallel()
	skipPlannerOnWindows(t)
	tests := []struct {
		name        string
		home        string
		masks       []string
		above, rest []string
	}{
		{"no masks", "/home/dev", nil, nil, nil},
		{"home on no mask", "/home/dev", []string{"/mnt/c", "/mnt/d"}, nil, []string{"/mnt/c", "/mnt/d"}},
		{"home under one mask", "/mnt/d/h", []string{"/mnt/c", "/mnt/d"}, []string{"/mnt/d"}, []string{"/mnt/c"}},
		{"home is a mask", "/mnt/d", []string{"/mnt/d"}, []string{"/mnt/d"}, nil},
		{"a shared prefix is not holding", "/mnt/dd/h", []string{"/mnt/d"}, nil, []string{"/mnt/d"}},
		{"a mask inside the home does not hold it", "/mnt/d", []string{"/mnt/d/x"}, nil, []string{"/mnt/d/x"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			above, rest := splitMasksAboveHome(tc.home, tc.masks)
			if !equalStrings(above, tc.above) || !equalStrings(rest, tc.rest) {
				t.Errorf("above %v rest %v, want above %v rest %v", above, rest, tc.above, tc.rest)
			}
		})
	}
}

// equalStrings compares two string slices, nil and empty equal.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
