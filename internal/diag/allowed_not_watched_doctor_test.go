package diag

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestCheckAdaptersWarnsOnAllowedNotWatched pins DI-07's doctor-side note
// (docs/plans/dashboard-install-gap-remediation-research-2026-09-02.md §5.4,
// §6.7): when [terminal.launch].allowed_tools names a tool an explicit
// [observer.watch].enabled_adapters list omits, checkAdapters (the
// `observer doctor` all-adapter summary) downgrades to StatusWarn and names
// the gap — the same one cmd/observer/start.go's startup WARN reports, via
// the shared diag.AllowedToolsNotWatched helper, so the two surfaces can
// never disagree.
func TestCheckAdaptersWarnsOnAllowedNotWatched(t *testing.T) {
	swapAdapterDetected(t, func(_ adapter.Adapter) bool { return false })

	cfg := config.Config{}
	cfg.Observer.Watch.EnabledAdapters = []string{"opencode", "cline"}
	cfg.Terminal.Launch.AllowedTools = []string{"opencode", "cline", "muse", "prime-agent"}

	check := checkAdapters(cfg)
	if check.Status != StatusWarn {
		t.Fatalf("Status = %v, want StatusWarn when allowed_tools has unwatched entries", check.Status)
	}
	var noteLine string
	for _, d := range check.Details {
		if strings.HasPrefix(d, "launchable but NOT watched") {
			noteLine = d
		}
	}
	if noteLine == "" {
		t.Fatalf("no DI-07 note in details: %v", check.Details)
	}
	// Exactly the unwatched pair, in allowed_tools order — opencode/cline ARE
	// watched and must not appear.
	if !strings.Contains(noteLine, "muse, prime-agent") {
		t.Errorf("note = %q, want the unwatched pair \"muse, prime-agent\"", noteLine)
	}
	if strings.Contains(noteLine, "opencode") || strings.Contains(noteLine, "cline") {
		t.Errorf("note wrongly lists a watched tool: %q", noteLine)
	}
}

// TestCheckAdaptersNoWarnWhenNothingUnwatched pins the negative: a nil
// enabled_adapters (the default — every adapter watched) or an
// enabled_adapters list that already covers every allowed tool leaves
// checkAdapters at StatusOK with no DI-07 note.
func TestCheckAdaptersNoWarnWhenNothingUnwatched(t *testing.T) {
	swapAdapterDetected(t, func(_ adapter.Adapter) bool { return false })

	tests := []struct {
		name string
		cfg  config.Config
	}{
		{
			name: "nil enabled_adapters (default: watch everything)",
			cfg: func() config.Config {
				var c config.Config
				c.Terminal.Launch.AllowedTools = []string{"muse", "prime-agent"}
				return c
			}(),
		},
		{
			name: "explicit list already covers every allowed tool",
			cfg: func() config.Config {
				var c config.Config
				c.Observer.Watch.EnabledAdapters = []string{"muse", "prime-agent", "opencode"}
				c.Terminal.Launch.AllowedTools = []string{"muse", "prime-agent"}
				return c
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := checkAdapters(tt.cfg)
			if check.Status != StatusOK {
				t.Fatalf("Status = %v, want StatusOK: details=%v", check.Status, check.Details)
			}
			for _, d := range check.Details {
				if strings.Contains(d, "launchable but NOT watched") {
					t.Errorf("unexpected DI-07 note when nothing is unwatched: %q", d)
				}
			}
		})
	}
}
