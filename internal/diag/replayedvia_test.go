package diag

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestReplayGatesFromRegistry: the walk finds the gates that ride another
// tool's registration (Cortex Code and Kimchi ride Claude Code), and only
// wired gate bindings (Grok's replayed lifecycle events are not gates).
func TestReplayGatesFromRegistry(t *testing.T) {
	got := map[string]replayGate{}
	for _, g := range replayGates() {
		got[g.tool] = g
		c, ok := integration.For(g.host)
		if !ok || c.Hook.Mechanism == integration.HookNone {
			t.Errorf("%s: replay host %q is not a hooked registry row", g.tool, g.host)
		}
	}
	for _, tool := range []string{"cortex-code", "kimchi"} {
		g, ok := got[tool]
		if !ok || g.host != "claude-code" || len(g.gates) == 0 {
			t.Errorf("%s: replay gate %+v, want gates riding claude-code", tool, g)
		}
	}
	if _, ok := got["grok"]; ok {
		t.Error("grok: its replayed bindings are lifecycle events, not gates")
	}
	// copilot-cli's Claude replay only stands in for its own registered
	// preToolUse (HookSpec.ReplayFallback, G2): its gate does not depend on
	// Claude Code's registration, so no row may say it does.
	if g, ok := got["copilot-cli"]; ok {
		t.Errorf("copilot-cli: replay gate %+v, want none (its own registration gates the call)", g)
	}
}

// TestReplayedViaChecks has one row per outcome.
func TestReplayedViaChecks(t *testing.T) {
	inUse := func(tools ...string) func(string) bool {
		return func(t string) bool {
			for _, x := range tools {
				if x == t {
					return true
				}
			}
			return false
		}
	}
	cases := []struct {
		name       string
		probe      replayedViaProbe
		wantRows   int
		wantStatus Status
		wantText   string
	}{
		{"not in use: no row", replayedViaProbe{inUse: inUse(), hostRegistered: func(string) (string, bool, error) { return "", false, nil }}, 0, StatusOK, ""},
		{"host registered", replayedViaProbe{inUse: inUse("cortex-code"), hostRegistered: func(string) (string, bool, error) { return "/h/.claude/settings.json", true, nil }}, 1, StatusOK, "which are registered"},
		{"host not registered", replayedViaProbe{inUse: inUse("cortex-code"), hostRegistered: func(string) (string, bool, error) { return "/h/.claude/settings.json", false, nil }}, 1, StatusWarn, "do not run"},
		{"host unreadable", replayedViaProbe{inUse: inUse("cortex-code"), hostRegistered: func(string) (string, bool, error) { return "", false, errors.New("parse") }}, 1, StatusWarn, "could not be read"},
		{"no probe", replayedViaProbe{}, 0, StatusOK, ""},
	}
	for _, tc := range cases {
		rows := replayedViaChecks(tc.probe)
		if len(rows) != tc.wantRows {
			t.Errorf("%s: %d rows %+v, want %d", tc.name, len(rows), rows, tc.wantRows)
			continue
		}
		if tc.wantRows == 0 {
			continue
		}
		r := rows[0]
		if r.Name != "cortex-code.hooks.replayed_via" || r.Status != tc.wantStatus || !strings.Contains(r.Message, tc.wantText) {
			t.Errorf("%s: %+v, want %s with %q", tc.name, r, tc.wantStatus, tc.wantText)
		}
	}
}

// TestCheckReplayedViaSandboxed: against an empty pinned home with no
// database, nothing is in use, so the production probe reports no row.
func TestCheckReplayedViaSandboxed(t *testing.T) {
	if rows := checkReplayedVia(t.Context(), t.TempDir(), "observer", nil, time.Now()); len(rows) != 0 {
		t.Errorf("empty home: %+v, want no rows", rows)
	}
}
