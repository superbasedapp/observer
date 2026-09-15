package diag

import (
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// cfgWithLists builds a config carrying exactly the two independent
// allow-lists AllowedToolsNotWatched cross-checks (audit DI-07), preserving
// the caller's nil-vs-empty intent for enabled_adapters.
func cfgWithLists(allowedTools, enabledAdapters []string) config.Config {
	var cfg config.Config
	cfg.Terminal.Launch.AllowedTools = allowedTools
	cfg.Observer.Watch.EnabledAdapters = enabledAdapters
	return cfg
}

// TestAllowedToolsNotWatched pins the DI-07 cross-check, including the
// nil-vs-empty rule enabled_adapters shares with adapter.Registry.Detected:
// nil = every adapter watched, non-nil empty = nothing watched.
func TestAllowedToolsNotWatched(t *testing.T) {
	cases := []struct {
		name            string
		allowedTools    []string
		enabledAdapters []string
		want            []string
	}{
		{
			name:            "nil_enabled_adapters_watches_everything",
			allowedTools:    []string{"codex", "muse"},
			enabledAdapters: nil,
			want:            nil,
		},
		{
			// The plain-shell pseudo-tool has no adapter and is never watched;
			// it must not be reported as a capture gap (review F6, 2026-09-03).
			name:            "shell_pseudo_tool_is_not_a_gap",
			allowedTools:    []string{"shell", "codex"},
			enabledAdapters: []string{"claude-code"},
			want:            []string{"codex"},
		},
		{
			name:            "explicit_list_reports_the_missing_tools_in_allowed_order",
			allowedTools:    []string{"muse", "codex", "goose"},
			enabledAdapters: []string{"claude-code", "codex"},
			want:            []string{"muse", "goose"},
		},
		{
			name:            "empty_non_nil_enabled_adapters_watches_nothing",
			allowedTools:    []string{"codex", "muse"},
			enabledAdapters: []string{},
			want:            []string{"codex", "muse"},
		},
		{
			name:            "all_present",
			allowedTools:    []string{"codex", "claude-code"},
			enabledAdapters: []string{"claude-code", "codex", "cursor"},
			want:            nil,
		},
		{
			name:            "no_allowed_tools_is_no_gap",
			allowedTools:    nil,
			enabledAdapters: []string{"claude-code"},
			want:            nil,
		},
		{
			name:            "blank_and_duplicate_entries_are_ignored",
			allowedTools:    []string{" ", "muse", "muse"},
			enabledAdapters: []string{"claude-code"},
			want:            []string{"muse"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := AllowedToolsNotWatched(cfgWithLists(tc.allowedTools, tc.enabledAdapters))
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("AllowedToolsNotWatched = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAdapterWatchedNilVsEmpty pins the shared membership helper both DI-06
// (the picker's per-tool watched flag) and DI-07 (the policy key) read, so the
// rule has exactly one owner.
func TestAdapterWatchedNilVsEmpty(t *testing.T) {
	if !AdapterWatched(cfgWithLists(nil, nil), "muse") {
		t.Error("nil enabled_adapters must mean every adapter is watched")
	}
	if AdapterWatched(cfgWithLists(nil, []string{}), "muse") {
		t.Error("non-nil empty enabled_adapters must mean nothing is watched")
	}
	if !AdapterWatched(cfgWithLists(nil, []string{"muse"}), "muse") {
		t.Error("a listed adapter must be watched")
	}
	if AdapterWatched(cfgWithLists(nil, []string{"codex"}), "muse") {
		t.Error("an unlisted adapter must not be watched")
	}
}
