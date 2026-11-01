package proxyroute

import (
	"fmt"
	"strings"
)

// VSCodeBaseURLHint returns no-mutation, paste-into-the-UI instructions for
// routing a legacy VS Code AI extension (the legacy Kilo Code extension,
// pending IDE-9) through the observer proxy via its "OpenAI Compatible"
// provider Base URL.
//
// It no longer applies to Cline (surface-gap IDE-8): current Cline builds
// keep their settings in ~/.cline/data/globalState.json, not VS Code's
// state.vscdb, and RegisterCline (cline.go) writes the route there. For the
// extensions it still covers, the route is MANUAL (RouteManual): they store
// their provider/base-URL config in VS Code's globalState (state.vscdb) +
// SecretStorage rather than a writable JSON file, and writing state.vscdb
// while VS Code is running is unsafe (VS Code caches globalState in memory
// and overwrites external edits on exit, grounded 2026-06-27).
//
// tool is a human label ("Kilo Code"); port is the observer proxy port.
func VSCodeBaseURLHint(port int, tool string) string {
	if strings.TrimSpace(tool) == "" {
		tool = "the extension"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "next: route %s through the observer proxy (manual - paste into the extension UI).\n", tool)
	fmt.Fprintln(&b, "  In the provider settings, choose \"OpenAI Compatible\" and set:")
	fmt.Fprintf(&b, "    Base URL: http://127.0.0.1:%d/v1\n", port)
	fmt.Fprintln(&b, "    API Key:  (leave your existing key - observer never reads it)")
	fmt.Fprintln(&b, "    Model ID: your usual model")
	fmt.Fprintln(&b, "  Why manual: the base URL lives in VS Code globalState (state.vscdb),")
	fmt.Fprintln(&b, "  not a writable config file, and editing it while VS Code runs is unsafe.")
	fmt.Fprintln(&b, "  Then send one message and confirm api_turns grew (observer status).")
	return b.String()
}
