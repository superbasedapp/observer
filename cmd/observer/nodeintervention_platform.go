package main

import "github.com/marmutapp/superbased-observer/internal/intervention"

// osDisplayNames names an OS in the node-control lines.
var osDisplayNames = map[string]string{"windows": "Windows", "darwin": "macOS"}

// nodeControlUnsupported is the node-control line on an OS that has no
// process-control backend (intervention.ProcessControlSupportedOn), and
// false on one that has it. On such an OS the controller is not available by
// design, so `observer enroll`, `observer org status` and `observer guard
// status` say so and name what still works, instead of reporting an
// authority or identity that "could not be verified" (WINNODE item 3: that
// wording read as a verification or security failure on a healthy Windows
// enrolment). A real verification failure on Linux keeps its own wording.
func nodeControlUnsupported(goos string) (string, bool) {
	if intervention.ProcessControlSupportedOn(goos) {
		return "", false
	}
	name := osDisplayNames[goos]
	if name == "" {
		name = goos
	}
	return "not supported on " + name + ": the process cutoff (stopping an AI tool's process when a hard budget runs out) runs only on Linux. " +
		"Org policy still applies here through the hooks, the proxy route and launch admission", true
}
