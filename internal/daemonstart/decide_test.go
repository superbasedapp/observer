package daemonstart

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// down is a launch that would start the daemon: routed, nothing answers,
// this node's own listener, nothing else in the way.
func down() Facts {
	return Facts{Wanted: true, Proxy: ProxyDown, OwnListener: true}
}

// TestDecideRows: one case per decideRules row (L-169).
func TestDecideRows(t *testing.T) {
	with := func(f func(*Facts)) Facts {
		in := down()
		f(&in)
		return in
	}
	held := func() bool { return true }
	cases := []struct {
		name   string
		in     Facts
		rule   string
		action Action
	}{
		{"a --no-proxy-route launch", with(func(f *Facts) { f.Wanted = false }), RuleNotWanted, ActionFallback},
		{"the proxy answers", with(func(f *Facts) { f.Proxy = ProxyServing }), RuleServing, ActionProceed},
		{"the proxy answers even with auto-start off", with(func(f *Facts) { f.Proxy = ProxyServing; f.OptOut = OptOutFlag }), RuleServing, ActionProceed},
		{"something that is not Observer answers on the port", with(func(f *Facts) { f.Proxy = ProxyForeign }), RuleForeignPort, ActionRefuse},
		{"the foreign port is reported even with auto-start off", with(func(f *Facts) { f.Proxy = ProxyForeign; f.OptOut = OptOutConfig }), RuleForeignPort, ActionRefuse},
		{"a build without capture.proxy (D-514)", with(func(f *Facts) { f.NotServed = "capture.proxy is not in this build" }), RuleNotServed, ActionFallback},
		{"[proxy].enabled = false", with(func(f *Facts) { f.NotServed = "the proxy is off on this node" }), RuleNotServed, ActionFallback},
		{"a --proxy override to another host", with(func(f *Facts) { f.OwnListener = false }), RuleNotOwn, ActionFallback},
		{"a dashboard terminal the daemon spawned", with(func(f *Facts) { f.DaemonChild = true }), RuleDaemonChild, ActionFallback},
		{"inside a sandbox", with(func(f *Facts) { f.InSandbox = true }), RuleInSandbox, ActionFallback},
		{"--no-start", with(func(f *Facts) { f.OptOut = OptOutFlag }), RuleOptedOut, ActionFallback},
		{"[launch].start_daemon = false", with(func(f *Facts) { f.OptOut = OptOutConfig }), RuleOptedOut, ActionFallback},
		{"a test binary with no stand-in", with(func(f *Facts) { f.OptOut = OptOutTestBinary }), RuleOptedOut, ActionFallback},
		{"the daemon lives in WSL, seen from Windows", with(func(f *Facts) { f.Other = OtherContext{Where: "WSL (Ubuntu)"} }), RuleOtherContext, ActionRefuse},
		{"a daemon holds the start lock", with(func(f *Facts) { f.DaemonRunning = true }), RuleAlreadyStarts, ActionWait},
		{"another launcher is starting it", with(func(f *Facts) { f.StartBusy = true }), RuleAlreadyStarts, ActionWait},
		{"the port is held but not answering", with(func(f *Facts) { f.PortHeld = held }), RulePortHeld, ActionRefuse},
		{"nothing in the way", down(), RuleStart, ActionStart},
		// The organization is no input: a managed node whose organization
		// owns the routes starts its daemon like any other (L-169 settles
		// LPD-2); only a daemon that cannot come up meets the refusal row of
		// the proxy-down fallback.
		{"a deliberate `observer service stop` earlier", down(), RuleStart, ActionStart},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Decide(c.in)
			if got.Rule != c.rule || got.Action != c.action {
				t.Fatalf("Decide(%+v) = %+v, want rule %q action %s", c.in, got, c.rule, c.action)
			}
		})
	}
}

// TestDecidePortHeldIsLazy: the bind probe runs only on the start row, so a
// daemon already starting (which may be binding the port) is never raced by
// the probe.
func TestDecidePortHeldIsLazy(t *testing.T) {
	calls := 0
	probe := func() bool { calls++; return false }
	for _, f := range []Facts{
		{Wanted: true, Proxy: ProxyServing, OwnListener: true, PortHeld: probe},
		{Wanted: true, Proxy: ProxyDown, OwnListener: true, DaemonRunning: true, PortHeld: probe},
		{Wanted: true, Proxy: ProxyDown, OwnListener: true, StartBusy: true, PortHeld: probe},
		{Wanted: true, Proxy: ProxyDown, OwnListener: true, OptOut: OptOutFlag, PortHeld: probe},
	} {
		Decide(f)
	}
	if calls != 0 {
		t.Fatalf("the port probe ran %d time(s) off the start row", calls)
	}
	f := down()
	f.PortHeld = probe
	if got := Decide(f); got.Action != ActionStart || calls != 1 {
		t.Fatalf("start row: %+v after %d probe(s), want start after 1", got, calls)
	}
}

// TestEveryDecideRuleIsCovered: a row added to the table needs a case.
func TestEveryDecideRuleIsCovered(t *testing.T) {
	covered := map[string]bool{
		RuleNotWanted: true, RuleServing: true, RuleForeignPort: true, RuleNotServed: true,
		RuleNotOwn: true, RuleDaemonChild: true, RuleInSandbox: true, RuleOptedOut: true,
		RuleOtherContext: true, RuleAlreadyStarts: true, RulePortHeld: true, RuleStart: true,
	}
	for _, r := range Rules() {
		if !covered[r] {
			t.Errorf("row %q has no case in TestDecideRows", r)
		}
	}
	if len(Rules()) != len(covered) {
		t.Errorf("table has %d rows, the test knows %d", len(Rules()), len(covered))
	}
}

// TestChooseMechanismRows: one case per mechanismRules row.
func TestChooseMechanismRows(t *testing.T) {
	cases := []struct {
		name string
		in   MechanismFacts
		want Mechanism
	}{
		{"a systemd user unit for this config", MechanismFacts{SystemdUnit: true, ServiceRunsThisConfig: true}, MechanismSystemd},
		{"a launchd agent for this config", MechanismFacts{LaunchAgent: true, ServiceRunsThisConfig: true}, MechanismLaunchd},
		{"a unit for another config starts in the background", MechanismFacts{SystemdUnit: true}, MechanismDetached},
		{"an agent for another config starts in the background", MechanismFacts{LaunchAgent: true}, MechanismDetached},
		{"the Windows sign-in entry", MechanismFacts{SignInBinary: true}, MechanismSignIn},
		{"nothing installed", MechanismFacts{}, MechanismDetached},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ChooseMechanism(c.in); got != c.want {
				t.Fatalf("ChooseMechanism(%+v) = %s, want %s", c.in, got, c.want)
			}
		})
	}
}

// TestOtherContextForRows: one case per contextRules row, plus the cases
// that stay in this context (the operator's WSL box with a stray Windows
// database among them).
func TestOtherContextForRows(t *testing.T) {
	wsl := Sibling{Origin: "wslhost:Ubuntu/dev", OS: "linux"}
	win := Sibling{Origin: "wsl-mnt:dev", OS: "windows"}
	cases := []struct {
		name  string
		in    ContextFacts
		where string
	}{
		{"Windows observer.exe, WSL daemon, no Windows database", ContextFacts{OnWindows: true, Siblings: []Sibling{wsl}}, "WSL (Ubuntu)"},
		{"Windows observer.exe, WSL daemon, a stray Windows database", ContextFacts{OnWindows: true, NativeDBExists: true, Siblings: []Sibling{wsl}}, "WSL (Ubuntu)"},
		{"WSL launcher that never ran a daemon, Windows one did", ContextFacts{Siblings: []Sibling{win}}, "Windows"},
		{"WSL box running its own daemon, a stray Windows database", ContextFacts{NativeDBExists: true, Siblings: []Sibling{win}}, ""},
		{"no other context at all", ContextFacts{}, ""},
		{"Windows with only its own database", ContextFacts{OnWindows: true, NativeDBExists: true}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := OtherContextFor(c.in)
			if got.Where != c.where {
				t.Fatalf("OtherContextFor(%+v).Where = %q, want %q", c.in, got.Where, c.where)
			}
			if got.Where != "" && !strings.Contains(got.Hint, "observer start") {
				t.Fatalf("hint %q does not say how to start it there", got.Hint)
			}
		})
	}
}

// TestCopy pins the lines every launcher prints.
func TestCopy(t *testing.T) {
	line := StartLine("claude", MechanismDetached, false) + "...." + Ready(4*time.Second)
	if line != "observer claude: the observer daemon was not running; starting it in the background ....... ready in 4 s" {
		t.Fatalf("start line = %q", line)
	}
	if got := StartLine("gemini", MechanismSystemd, true); !strings.Contains(got, "was stopped; starting it again through its systemd user unit") {
		t.Fatalf("stopped start line = %q", got)
	}
	if got := NotReady(30*time.Second, "/h/.observer/daemon.log"); got != " no answer after 30 s; log: /h/.observer/daemon.log" {
		t.Fatalf("not ready = %q", got)
	}
	if got := Failed(errors.New("exec: no such file"), ""); got != " failed: exec: no such file" {
		t.Fatalf("failed = %q", got)
	}
	if got := Exited("exit status 1", "/l"); got != " it exited before its proxy answered (exit status 1); log: /l" {
		t.Fatalf("exited = %q", got)
	}
	if got := Ready(300 * time.Millisecond); got != " ready in under 1 s" {
		t.Fatalf("ready = %q", got)
	}
	other := RefuseLine("claude", RuleOtherContext, "8820", OtherContext{Where: "WSL (Ubuntu)", Hint: "open a WSL (Ubuntu) terminal and run `observer start`"})
	for _, want := range []string{"WSL (Ubuntu)", "not starting a second one here", "observer start"} {
		if !strings.Contains(other, want) {
			t.Fatalf("other-context line %q lacks %q", other, want)
		}
	}
	for _, rule := range []string{RuleForeignPort, RulePortHeld} {
		if got := RefuseLine("codex", rule, "8820", OtherContext{}); !strings.Contains(got, "8820") || !strings.Contains(got, "not starting a daemon") {
			t.Fatalf("%s line = %q", rule, got)
		}
	}
	if RefuseLine("x", RuleStart, "1", OtherContext{}) != "" {
		t.Fatal("a non-refusal row has no refusal line")
	}
}
