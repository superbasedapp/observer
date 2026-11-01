package managedsettings

import "testing"

// TestObserverWiringCoversEveryLayer pins CLI-10: every managed layer says
// whether it carries Observer's own route and hooks, and the table names no
// layer that does not exist.
func TestObserverWiringCoversEveryLayer(t *testing.T) {
	seen := map[string]bool{}
	for _, l := range Layers() {
		seen[l.FileID] = true
		if ObserverWiring(l.FileID) == "" {
			t.Errorf("layer %s has no observerWiring sentence", l.FileID)
		}
	}
	for id := range observerWiring {
		if !seen[id] {
			t.Errorf("observerWiring names %s, which is not a layer", id)
		}
	}
}
