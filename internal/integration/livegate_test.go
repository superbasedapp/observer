package integration

import (
	"strings"
	"testing"
)

// TestLiveGateText pins the one shared wording (DEC-12): lane L4's cross-OS
// hook gate reads the same, so doctor lines agree across lanes.
func TestLiveGateText(t *testing.T) {
	for _, tc := range []struct {
		gate    LiveGate
		waiting bool
		text    string
	}{
		{"", false, ""},
		{"  ", false, ""},
		{"LC11", true, "built, waiting on live check LC11"},
		{" LC37 ", true, "built, waiting on live check LC37"},
	} {
		if got := tc.gate.Waiting(); got != tc.waiting {
			t.Errorf("%q.Waiting() = %v, want %v", tc.gate, got, tc.waiting)
		}
		if got := tc.gate.Text(); got != tc.text {
			t.Errorf("%q.Text() = %q, want %q", tc.gate, got, tc.text)
		}
	}
}

// TestLiveGateLookups gates a synthetic row's route and hook writers and
// checks every accessor sees it, including through a "-windows" target, and
// that an ungated row answers zero.
func TestLiveGateLookups(t *testing.T) {
	const tool = "synthetic-livegate"
	registry[tool] = Capability{
		Tool:       tool,
		ProxyProbe: &ProxyRoute{Kind: RouteConfigFile, Note: "writes x", LiveGate: "LC99"},
		Hook:       HookSpec{Mechanism: HookClaudeSettings, LiveGate: "LC98"},
	}
	t.Cleanup(func() { delete(registry, tool) })

	if g := RouteLiveGate(tool); g != "LC99" {
		t.Errorf("RouteLiveGate = %q, want LC99", g)
	}
	if g := RouteLiveGate(tool + "-windows"); g != "LC99" {
		t.Errorf("RouteLiveGate(-windows) = %q, want LC99", g)
	}
	if g := HookLiveGate(tool + "-windows"); g != "LC98" {
		t.Errorf("HookLiveGate(-windows) = %q, want LC98", g)
	}
	if g := RouteLiveGate("claude-code"); g.Waiting() {
		t.Errorf("claude-code route gated: %q", g)
	}
	if g := RouteLiveGate("no-such-tool"); g.Waiting() {
		t.Errorf("unknown tool gated: %q", g)
	}
	var got []string
	for _, w := range LiveGatedWriters() {
		if w.Tool == tool {
			got = append(got, w.Kind+":"+string(w.Gate)+":"+w.Note)
		}
	}
	if strings.Join(got, ",") != "hooks:LC98:"+string(HookClaudeSettings)+",route:LC99:writes x" {
		t.Errorf("LiveGatedWriters for the synthetic row = %v", got)
	}
}

// TestLiveCheckIDShape pins liveCheckID, one case per accepted and refused
// shape.
func TestLiveCheckIDShape(t *testing.T) {
	for id, ok := range map[string]bool{
		"LC11": true, "LC26b": true, "LCR-1": true, "LCR-12": true,
		"LC": false, "LC0": false, "LC11B": false, "LCR1": false, "LCR-": false, "lc11": false, " LC11": false, "LC11 ": false, "LCX-1": false,
	} {
		if got := liveCheckID.MatchString(id); got != ok {
			t.Errorf("liveCheckID(%q) = %v, want %v", id, got, ok)
		}
	}
}

// TestLiveGatedRowsAreNotVerified pins DEC-12's honesty rule for the real
// registry: a gated route writer is never a verified Proxy route (the row
// stays probe_required with a nil Proxy), and every gate names a live check.
func TestLiveGatedRowsAreNotVerified(t *testing.T) {
	for _, w := range LiveGatedWriters() {
		c, _ := For(w.Tool)
		if !liveCheckID.MatchString(string(w.Gate)) {
			t.Errorf("%s %s writer: gate %q is not a live-check id (LC<n>, LCR-<n> or LC<n><letter>)", w.Tool, w.Kind, w.Gate)
		}
		if w.Kind != "route" {
			continue
		}
		if c.Proxy != nil {
			t.Errorf("%s: a gated route writer has a verified Proxy route", w.Tool)
		}
		if c.Routability != RouteStatusProbeRequired {
			t.Errorf("%s: a gated route writer's row is %q, want probe_required", w.Tool, c.Routability)
		}
		if c.ProxyProbe == nil || c.ProxyProbe.LiveGate != w.Gate {
			t.Errorf("%s: the gate is not on the ProxyProbe binding", w.Tool)
		}
	}
}

// TestRouteCredentialFileSet pins FU-33's declared set: the probe writers
// (kimi-code, qwen-code, crush, cline), cline-cli's launcher and the other
// launchers and verified routes that rewrite a credential-bearing file. A
// "-windows" target answers for its base row.
func TestRouteCredentialFileSet(t *testing.T) {
	got := strings.Join(CredentialFileRouteTools(), ",")
	for _, want := range []string{"cline", "cline-cli", "crush", "kimi-code", "qwen-code", "claude-code", "codex", "hermes", "pi", "prime-agent"} {
		if !strings.Contains(","+got+",", ","+want+",") {
			t.Errorf("%s missing from the route credential-file set %q", want, got)
		}
	}
	if !RouteSharesCredentialFile("claude-code-windows") {
		t.Error("claude-code-windows does not answer for its base row")
	}
	if RouteSharesCredentialFile("opencode") {
		t.Error("opencode (an env-only launcher) is declared")
	}
}

// TestAutoWiredNow: a hook is advertised as wired only when it has a
// mechanism, is auto-wired and its writer is not waiting on a live check.
func TestAutoWiredNow(t *testing.T) {
	for _, tc := range []struct {
		name string
		h    HookSpec
		want bool
	}{
		{"no mechanism", HookSpec{AutoWired: true}, false},
		{"manual", HookSpec{Mechanism: HookClaudeSettings}, false},
		{"auto-wired", HookSpec{Mechanism: HookClaudeSettings, AutoWired: true}, true},
		{"auto-wired but gated", HookSpec{Mechanism: HookClaudeSettings, AutoWired: true, LiveGate: "LC18"}, false},
	} {
		if got := tc.h.AutoWiredNow(); got != tc.want {
			t.Errorf("%s: AutoWiredNow() = %v, want %v", tc.name, got, tc.want)
		}
	}
	if c, _ := For("cortex-code"); c.Hook.AutoWiredNow() {
		t.Error("the gated cortex-code hook reads as wired")
	}
}

// TestRowlessGatedWriters pins the rowless gated writers: each row is one
// live-check id, LiveGatedWriters lists every row, and LiveGates waits while
// any gate does and names them all.
func TestRowlessGatedWriters(t *testing.T) {
	listed := map[string]bool{}
	for _, w := range LiveGatedWriters() {
		listed[w.Tool+"/"+w.Kind+"/"+string(w.Gate)] = true
	}
	for _, w := range rowlessGatedWriters {
		if !liveCheckID.MatchString(string(w.Gate)) {
			t.Errorf("%s %s: gate %q is not a live-check id", w.Tool, w.Kind, w.Gate)
		}
		if !listed[w.Tool+"/"+w.Kind+"/"+string(w.Gate)] {
			t.Errorf("%s %s %s is not in LiveGatedWriters", w.Tool, w.Kind, w.Gate)
		}
	}
	relay := RowlessWriterGates("claude-code", WriterKindRelay)
	if !relay.Waiting() || relay.Text() != "built, waiting on live check LC6 and LC14" {
		t.Fatalf("relay gates = %v (%q)", relay, relay.Text())
	}
	for _, tool := range []string{"claude-code", "codex"} {
		if g := RowlessWriterGates(tool, WriterKindHookBridge); g.Text() != "built, waiting on live check LC6" {
			t.Errorf("%s hook bridge gates = %v (%q)", tool, g, g.Text())
		}
	}
	if g := (LiveGates{"", " "}); g.Waiting() || g.Text() != "" {
		t.Error("empty gates must not wait")
	}
	if g := RowlessWriterGates("no-such-tool", WriterKindRelay); g.Waiting() {
		t.Error("an unknown tool has no gate")
	}
}

// TestLiveGateFindingWording (FU-195): a gate whose live check ran and found
// the host does not run the hook says so instead of "waiting"; any other
// gate keeps the waiting wording, and a joined gate never reads a finding.
func TestLiveGateFindingWording(t *testing.T) {
	for id := range liveCheckFindings {
		if !IsLiveCheckID(id) {
			t.Errorf("finding %q is not a live-check id", id)
		}
		g := LiveGate(id)
		if !g.Waiting() || !strings.HasPrefix(g.Text(), "built, not enforceable: live check "+id+" found ") {
			t.Errorf("%s: Text = %q", id, g.Text())
		}
	}
	if got := LiveGate("LC6").Text(); got != "built, waiting on live check LC6" {
		t.Errorf("LC6: %q", got)
	}
	if f := LiveGate("LCR-91 and LC6").Finding(); f != "" {
		t.Errorf("a joined gate read a finding: %q", f)
	}
}
