package integration

import "testing"

// TestGUILaunchIDsAreDisjointFromToolIDs pins that the GUI launch-id key
// space never overlaps the registry TOOL key space. The dashboard's
// preflight / install / launch seams resolve an id through ONE ladder —
// terminal row first, then GUILaunchFor — and a shared id would make the
// answer depend on ladder order (the 2026-09-03 `grokbot` collision: the
// desktop-app adapter's GUI row was named after the tool itself; it is now
// `grokbot-desktop`). A disjoint key space keeps [terminal.launch].
// allowed_tools entries unambiguous too: an allowed id is exactly one thing.
func TestGUILaunchIDsAreDisjointFromToolIDs(t *testing.T) {
	for _, g := range GUILaunchables() {
		if _, isTool := registry[g.Spec.ID]; isTool {
			t.Errorf("GUI launch id %q is also a registry tool id — rename the GUI row (e.g. %q)", g.Spec.ID, g.Spec.ID+"-desktop")
		}
	}
}
