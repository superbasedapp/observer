package main

import (
	"path/filepath"
	"strings"
)

// gui_instance.go is the IDE-2 process probe (ledger AP-043) behind
// guilaunch.Inputs.InstanceRunning: is an instance of the GUI app at bin
// already running for this user? guilaunch asks it only for a launch that
// would hand its arguments to a running instance and exit (a single-instance
// child-env app, or a macOS `open -a` launch); a yes records the wrap as not
// applied with "close all windows first". Read-only and exec-free: Windows
// walks a ToolHelp snapshot, Linux reads /proc/<pid>/exe links, macOS reads
// each process's executable path through sysctl. Every answer it cannot
// prove is false, which leaves the launch verdict as it was (the cold-start
// caveat still rides the note).

// guiInstanceRunning is the production probe (a var so tests can stub it).
var guiInstanceRunning = func(bin string) bool {
	if strings.TrimSpace(bin) == "" {
		return false
	}
	return platformGUIInstanceRunning(bin)
}

// guiInstanceImage is the process image name a Windows probe matches for
// bin: the base name of a .exe path in either separator spelling, "" for
// anything else (a .cmd shim, a script), which the probe cannot match.
func guiInstanceImage(bin string) string {
	base := bin
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	if !strings.EqualFold(filepath.Ext(base), ".exe") {
		return ""
	}
	return base
}

// guiBundleExecDir is the "<bundle>.app/Contents/MacOS/" prefix every
// process of the macOS app bundle bin belongs to runs from: bin itself when
// it is a bundle, else the bundle that holds it (the `code` launcher script
// inside Visual Studio Code.app). "" when bin is in no bundle.
func guiBundleExecDir(bin string) string {
	parts := strings.Split(filepath.ToSlash(bin), "/")
	for i, p := range parts {
		if strings.HasSuffix(p, ".app") {
			return strings.Join(parts[:i+1], "/") + "/Contents/MacOS/"
		}
	}
	return ""
}
