package sandboxsetup

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
)

// Fix round 3, item 5: the copy nits of the 2026-11-07 re-run.

// TestJoinSentencesEndsTheFirst (O-1) is one case per shape.
func TestJoinSentencesEndsTheFirst(t *testing.T) {
	cases := []struct{ a, b, want string }{
		{"", "Second.", "Second."},
		{"First.", "", "First."},
		{"First.", "Second.", "First. Second."},
		{"first without a stop", "Second.", "first without a stop. Second."},
		{"Is it?", "Second.", "Is it? Second."},
		{"  padded  ", "Second.", "padded. Second."},
	}
	for _, tc := range cases {
		if got := joinSentences(tc.a, tc.b); got != tc.want {
			t.Errorf("joinSentences(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestAppleImageReasonDoesNotRunOn (O-1): the probe's image reason, which
// has no full stop, and the guide's key sentence read as two sentences.
func TestAppleImageReasonDoesNotRunOn(t *testing.T) {
	in := base(t, sandboxbackend.BackendAppleContainer)
	in.Host, in.Family, in.Arch = sandboxbackend.HostMacOS, FamilyMacOS, "arm64"
	in.Probe = &sandboxselect.Probe{Verdict: "image_missing", Reason: "[terminal.sandbox.apple_container].image must name a linux/arm64 image pinned by digest (name@sha256:<64 hex>) holding the agent and a linux/arm64 observer"}
	st := stepOf(t, Build(in), "apple-container-image")
	if !strings.Contains(st.Reason, "linux/arm64 observer. Set [terminal.sandbox.apple_container].image") {
		t.Fatalf("reason = %q", st.Reason)
	}
}

// TestNoStepPromisesASetupTerminal (O-2): no step's sentence says it runs in
// a setup terminal, since any step can read as a guide Observer does not run
// (the kill switch, elevation off, an unset key); the button or the CLI says
// where a runnable step runs.
func TestNoStepPromisesASetupTerminal(t *testing.T) {
	all := append([]Prereq(nil), prereqTable...)
	for _, p := range genericPrereqs {
		all = append(all, p)
	}
	for _, p := range all {
		for _, r := range p.Remedies {
			if strings.Contains(strings.ToLower(r.Display), "setup terminal") {
				t.Errorf("%s: display %q promises a setup terminal", p.ID, r.Display)
			}
		}
	}
}
