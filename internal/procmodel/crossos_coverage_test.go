package procmodel

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestCrossOSBasenamesCoverEveryEnabledAdapter pins the invariant that every
// adapter the daemon scans by default has a cross-OS attribution anchor. A new
// adapter added to config.Default() without a DefaultCrossOSToolBasenames entry
// would silently get NO Windows process attribution (the map returns nil and
// cross-OS never guesses), so this test fails loudly and points the author at
// the map — the same allow-list discipline EnabledAdapters enforces elsewhere.
func TestCrossOSBasenamesCoverEveryEnabledAdapter(t *testing.T) {
	t.Parallel()
	for _, tool := range config.Default().Observer.Watch.EnabledAdapters {
		// Browser-extension-fed adapters have no per-tool local process to
		// attribute: all five *-web tools share the browser's own process,
		// so a basename anchor would misattribute across them. Dispatch on
		// the capability (registry Hook mechanism), never the tool name.
		if cap, ok := integration.For(tool); ok && cap.Hook.Mechanism == integration.HookBrowserExtension {
			continue
		}
		// A proxy-only row (custom-agent) is the developer's own program
		// with no vendor binary, so there is no basename to anchor on.
		if cap, ok := integration.For(tool); ok && cap.ProxyOnlyCapture {
			continue
		}
		set := DefaultCrossOSToolBasenames[tool]
		if len(set) == 0 {
			t.Errorf("adapter %q is enabled by default but has no DefaultCrossOSToolBasenames entry — Windows process attribution will silently no-op for it; add a basename set (node.exe/node at minimum)", tool)
		}
	}
}
