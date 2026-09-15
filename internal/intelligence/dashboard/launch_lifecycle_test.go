package dashboard

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestLaunchSurfacesGateOnTerminalLaunchable pins that the dashboard's launch
// surfaces read integration.TerminalLaunchable (grounded LaunchSpec AND an
// advertised lifecycle), not the bare shape predicate. There is no
// registry-override seam in this package, so the assertion is an equivalence
// against the live registry: launchableTools() and launchSubcommand() must
// agree with TerminalLaunchable row for row. The moment a row is flipped to
// deprecated/dead, an un-updated surface stops matching and this goes red.
func TestLaunchSurfacesGateOnTerminalLaunchable(t *testing.T) {
	inPicker := map[string]bool{}
	for _, tool := range launchableTools() {
		inPicker[tool] = true
	}
	for _, c := range integration.Capabilities() {
		want := integration.TerminalLaunchable(c)
		if inPicker[c.Tool] != want {
			t.Errorf("launchableTools(): %q present = %v, want %v (Launchable=%v Lifecycle=%q)",
				c.Tool, inPicker[c.Tool], want, c.Handoff.Launchable(), c.Lifecycle.String())
		}
		if _, ok := launchSubcommand(c.Tool); ok != want {
			t.Errorf("launchSubcommand(%q) ok = %v, want %v", c.Tool, ok, want)
		}
	}
	if _, ok := launchSubcommand("definitely-not-a-tool"); ok {
		t.Error("launchSubcommand resolved an unknown tool")
	}
}

// TestResumeInfoForToolGatesHandoffOnLifecycle pins the session-detail resume
// block: the "handoff" kind means "fork this into an embedded terminal", so
// it must be gated on TerminalLaunchable — offering a handoff fork into a
// product Observer refuses to launch would be an affordance that cannot fire.
// Native resume is unaffected: it is a property of the tool's own CLI.
func TestResumeInfoForToolGatesHandoffOnLifecycle(t *testing.T) {
	for _, c := range integration.Capabilities() {
		got := resumeInfoForTool(c.Tool)
		switch {
		case c.Resume.Kind == integration.ResumeNative:
			if got.Kind != "native" {
				t.Errorf("resumeInfoForTool(%q).Kind = %q, want native", c.Tool, got.Kind)
			}
		case integration.TerminalLaunchable(c):
			if got.Kind != "handoff" {
				t.Errorf("resumeInfoForTool(%q).Kind = %q, want handoff", c.Tool, got.Kind)
			}
		default:
			if got.Kind != "none" {
				t.Errorf("resumeInfoForTool(%q).Kind = %q, want none", c.Tool, got.Kind)
			}
		}
	}
	if got := resumeInfoForTool("definitely-not-a-tool"); got.Kind != "none" {
		t.Errorf("resumeInfoForTool(unknown).Kind = %q, want none", got.Kind)
	}
}

// TestHandoffTargetsLaunchableFlagFollowsLifecycle pins the handoff target
// picker's per-row Launchable flag: a row is still LISTED whatever its
// lifecycle (the file-carry lane always works and capture never stops), but
// the launch flag is TerminalLaunchable AND the runtime availability.
func TestHandoffTargetsLaunchableFlagFollowsLifecycle(t *testing.T) {
	byTool := map[string]handoffTarget{}
	for _, tgt := range handoffTargets(true) {
		byTool[tgt.Tool] = tgt
	}
	for _, c := range integration.Capabilities() {
		tgt, ok := byTool[c.Tool]
		if !ok {
			t.Errorf("handoffTargets() dropped %q — every row stays listed, only the launch flag moves", c.Tool)
			continue
		}
		if want := integration.TerminalLaunchable(c); tgt.Launchable != want {
			t.Errorf("handoffTargets(): %q Launchable = %v, want %v", c.Tool, tgt.Launchable, want)
		}
	}
	// launchEnabled=false forces every flag off regardless of capability.
	for _, tgt := range handoffTargets(false) {
		if tgt.Launchable {
			t.Errorf("handoffTargets(false): %q Launchable = true with no launcher wired", tgt.Tool)
		}
	}
}
