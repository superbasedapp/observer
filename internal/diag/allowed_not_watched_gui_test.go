package diag

import (
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// anyGUIRows returns one HOST launch id (a row with no adapter of its own) and
// one ADAPTER-CARRIED launch id plus the adapter behind it. The rows are
// discovered from the live registry rather than hardcoded, so this table keeps
// pinning the RULE as the GUI row set evolves. It skips when the registry does
// not (yet) advertise both shapes.
func anyGUIRows(t *testing.T) (hostID, carriedID, carriedAdapter string) {
	t.Helper()
	for _, g := range integration.GUILaunchables() {
		if !g.Advertised() {
			continue
		}
		if g.Adapter == "" && hostID == "" {
			hostID = g.Spec.ID
		}
		if g.Adapter != "" && carriedID == "" {
			carriedID, carriedAdapter = g.Spec.ID, g.Adapter
		}
	}
	if hostID == "" || carriedID == "" {
		t.Skip("registry does not advertise both a GUI host row and an adapter-carried GUI row")
	}
	return hostID, carriedID, carriedAdapter
}

// TestAllowedToolsNotWatchedGUIIDs pins the capture-gap WARN's lookup ladder:
// allowed_tools is ONE list keyed by launch id, and a GUI launch id is not an
// adapter name. Before this rung existed, a correctly configured node warned
// "lists 10 tool(s) that your explicit enabled_adapters does not watch:
// vscode, cursor-ide, …" at every start (2026-09-03 live verification).
func TestAllowedToolsNotWatchedGUIIDs(t *testing.T) {
	hostID, carriedID, carriedAdapter := anyGUIRows(t)

	cases := []struct {
		name            string
		allowedTools    []string
		enabledAdapters []string
		want            []string
	}{
		{
			// Rung 1 unchanged: a registry ADAPTER the watcher is not watching
			// is still the honest capture gap this check exists to name.
			name:            "registry_tool_unwatched_is_still_flagged",
			allowedTools:    []string{"codex"},
			enabledAdapters: []string{"claude-code"},
			want:            []string{"codex"},
		},
		{
			// A pure editor HOST has no adapter of its own, so there is
			// nothing for enabled_adapters to omit. It must never be flagged —
			// not even under an explicit watch-nothing list.
			name:            "gui_host_id_is_never_flagged",
			allowedTools:    []string{hostID},
			enabledAdapters: []string{"claude-code"},
			want:            nil,
		},
		{
			name:            "gui_host_id_is_not_flagged_even_when_watching_nothing",
			allowedTools:    []string{hostID},
			enabledAdapters: []string{},
			want:            nil,
		},
		{
			// An adapter-carried IDE defers to the adapter BEHIND it.
			name:            "gui_row_whose_adapter_is_watched_is_not_flagged",
			allowedTools:    []string{carriedID},
			enabledAdapters: []string{carriedAdapter},
			want:            nil,
		},
		{
			// …and is flagged under the GUI ID (the operator's own spelling in
			// allowed_tools), not under the adapter name they never wrote.
			name:            "gui_row_whose_adapter_is_unwatched_is_flagged_under_the_gui_id",
			allowedTools:    []string{carriedID},
			enabledAdapters: []string{"claude-code"},
			want:            []string{carriedID},
		},
		{
			// Rung 3 unchanged: an id nothing recognises is most likely a
			// typo'd adapter name, and naming it stays the useful answer.
			name:            "unknown_id_keeps_the_original_behaviour",
			allowedTools:    []string{"not-a-tool-or-a-gui-row"},
			enabledAdapters: []string{"claude-code"},
			want:            []string{"not-a-tool-or-a-gui-row"},
		},
		{
			// The mixed real-world shape: adapters and GUI ids in one list,
			// reported in the operator's own order with the hosts absent.
			name:            "mixed_list_reports_only_the_real_gaps_in_allowed_order",
			allowedTools:    []string{"codex", hostID, carriedID, "claude-code"},
			enabledAdapters: []string{"claude-code", carriedAdapter},
			want:            []string{"codex"},
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

// TestGUILaunchWatched pins the shared helper the dashboard picker's per-row
// `watched` flag and the start-up WARN both read, so the two surfaces have one
// owner and can never disagree.
func TestGUILaunchWatched(t *testing.T) {
	t.Parallel()

	host := integration.GUILaunchable{Spec: integration.GUILaunchSpec{ID: "editor-host"}}
	carried := integration.GUILaunchable{
		Spec:    integration.GUILaunchSpec{ID: "vendor-ide"},
		Adapter: "vendor",
	}

	cases := []struct {
		name            string
		row             integration.GUILaunchable
		enabledAdapters []string
		want            bool
	}{
		{"host_with_nil_list", host, nil, true},
		{"host_with_explicit_list_omitting_it", host, []string{"claude-code"}, true},
		{"host_with_watch_nothing_list", host, []string{}, true},
		{"carried_with_nil_list", carried, nil, true},
		{"carried_adapter_watched", carried, []string{"vendor"}, true},
		{"carried_adapter_unwatched", carried, []string{"claude-code"}, false},
		{"carried_with_watch_nothing_list", carried, []string{}, false},
		{
			// The GUI ID being in enabled_adapters proves nothing: the watcher
			// keys on ADAPTER names, so only the adapter behind the row counts.
			name:            "carried_row_id_in_the_watch_list_does_not_count",
			row:             carried,
			enabledAdapters: []string{"vendor-ide"},
			want:            false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cfg config.Config
			cfg.Observer.Watch.EnabledAdapters = tc.enabledAdapters
			if got := GUILaunchWatched(cfg, tc.row); got != tc.want {
				t.Fatalf("GUILaunchWatched = %v, want %v", got, tc.want)
			}
		})
	}
}
