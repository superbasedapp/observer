package clientwire

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestGatedHookIsNotSupported: a hook writer switched off behind a live
// check (DEC-12) is never offered for registration, so init, the Tools
// page and the setup wizard all refuse it.
func TestGatedHookIsNotSupported(t *testing.T) {
	for _, w := range integration.LiveGatedWriters() {
		if w.Kind != "hooks" {
			continue
		}
		if HookSupported(w.Tool) {
			t.Errorf("%s: HookSupported is true for a gated writer (%s)", w.Tool, w.Gate.Text())
		}
	}
}
