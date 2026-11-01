//go:build !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"slices"
	"strings"
	"testing"
)

// TestMXCProbeTakesTheDaemonsObserverDir (lane LEFT-SBX, the SBX-P3D
// merge's left item): the probe helper reads the content store of the
// observer dir the daemon passes; started by hand with none it refuses,
// naming the flag and the directory its own shell's config would have used.
func TestMXCProbeTakesTheDaemonsObserverDir(t *testing.T) {
	if why := mxcProbeDirRefusal(`C:\Users\dev\.observer`, `C:\Users\dev\.observer`); why != "" {
		t.Fatalf("with the flag: %q", why)
	}
	why := mxcProbeDirRefusal("", `C:\Users\dev\.observer`)
	if !strings.Contains(why, mxcFlagObserverDir) || !strings.Contains(why, `C:\Users\dev\.observer`) {
		t.Fatalf("without the flag: %q", why)
	}
	if argv := mxcProbeArgv(`C:\obs`); !slices.Contains(argv, mxcFlagObserverDir) {
		t.Fatalf("the daemon's probe argv lacks the flag: %v", argv)
	}
}
