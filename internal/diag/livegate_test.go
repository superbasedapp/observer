package diag

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestCheckLiveGatedWriters: the doctor names every gated registry writer
// in the shared DEC-12 wording, and stays OK (nothing is broken).
func TestCheckLiveGatedWriters(t *testing.T) {
	c := checkLiveGatedWriters()
	if c.Name != "writers.live_gate" || c.Status != StatusOK {
		t.Fatalf("check = %+v", c)
	}
	gated := integration.LiveGatedWriters()
	if len(c.Details) != len(gated) {
		t.Fatalf("details = %d, gated writers = %d", len(c.Details), len(gated))
	}
	for i, g := range gated {
		want := g.Tool + " " + g.Kind + " writer: " + g.Gate.Text()
		if !strings.HasPrefix(c.Details[i], want) {
			t.Errorf("detail %d = %q, want prefix %q", i, c.Details[i], want)
		}
	}
}

// TestCheckLiveGatedWritersNamesTheRowlessWriters: the relay (LC6, LC14)
// and the AW-37 hook bridge (LC6) are in the doctor's writers.live_gate
// list with the shared wording.
func TestCheckLiveGatedWritersNamesTheRowlessWriters(t *testing.T) {
	c := checkLiveGatedWriters()
	joined := strings.Join(c.Details, "\n")
	for _, want := range []string{
		"claude-code hook_bridge writer: built, waiting on live check LC6",
		"codex hook_bridge writer: built, waiting on live check LC6",
		"claude-code relay writer: built, waiting on live check LC6",
		"claude-code relay writer: built, waiting on live check LC14",
		// FU-160 / FU-195: the Xcode Gemini hook writer stays off on
		// LCR-91's finding (no BeforeTool).
		"gemini-cli host_hooks writer: built, not enforceable: live check LCR-91 found",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("writers.live_gate lacks %q:\n%s", want, joined)
		}
	}
	// FU-145: the Xcode Claude and Codex hook writers passed LCR-89 and
	// LCR-90 (2026-10-28, Mac round 5b) and are switched on, so the doctor
	// no longer lists them as waiting.
	for _, gone := range []string{"LCR-89", "LCR-90", "claude-code host_hooks", "codex host_hooks"} {
		if strings.Contains(joined, gone) {
			t.Errorf("writers.live_gate still names %q:\n%s", gone, joined)
		}
	}
}
