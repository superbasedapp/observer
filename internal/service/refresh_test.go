package service

import (
	"reflect"
	"strings"
	"testing"
)

// TestDecideRefresh has one case per row of refreshRules (T-753): an
// in-place upgrade must never leave the old daemon running while claiming
// the service started, and must never restart the proxy under a live route.
func TestDecideRefresh(t *testing.T) {
	stale := RefreshInputs{Active: true, ExecChanged: true, ProxyListening: true}
	with := func(f func(*RefreshInputs)) RefreshInputs { in := stale; f(&in); return in }
	cases := []struct {
		name   string
		in     RefreshInputs
		action RefreshAction
		reason string
	}{
		{"stopped unit, install --now", RefreshInputs{StartIfInactive: true}, RefreshStart, ""},
		{"stopped unit, upgrade", RefreshInputs{}, RefreshLeaveStopped, ""},
		{"running this binary", RefreshInputs{Active: true, ProxyListening: true, Routes: []string{"claude-code (x)"}}, RefreshNone, ""},
		{"replaced binary, no proxy listener (minimal edition)", with(func(in *RefreshInputs) { in.ProxyListening = false; in.Routes = []string{"claude-code (x)"} }), RefreshRestart, "no proxy listener"},
		{"replaced binary, probe failed", with(func(in *RefreshInputs) { in.ProbeErr = "permission denied" }), RefreshAdvise, "could not be checked"},
		{"replaced binary, route active", with(func(in *RefreshInputs) { in.Routes = []string{"claude-code (/h/.claude/settings.json)"} }), RefreshAdvise, "proxy route is active: claude-code"},
		{"replaced binary, open proxy connection", with(func(in *RefreshInputs) { in.ProxyClients = 2 }), RefreshAdvise, "2 open connection"},
		{"replaced binary, idle proxy", stale, RefreshRestart, "no proxy route is active"},
		{"executable unreadable, idle proxy", with(func(in *RefreshInputs) { in.ExecChanged, in.ExecUnknown = false, true }), RefreshRestart, ""},
		{"new ExecStart arguments, idle proxy", with(func(in *RefreshInputs) { in.ExecChanged, in.ExecStartChanged = false, true }), RefreshRestart, ""},
		// UPD-9 interlock: a daemon started under a unit without the update
		// hand-over (no NOTIFY_SOCKET) is refused every in-place update until
		// it restarts under the rewritten unit, so the same binary still
		// needs the restart, under the same proxy-safety rows.
		{"same binary, started without the hand-over, idle proxy", with(func(in *RefreshInputs) { in.ExecChanged, in.HandoverMissing = false, true }), RefreshRestart, "no proxy route is active"},
		{"same binary, started without the hand-over, route active", with(func(in *RefreshInputs) {
			in.ExecChanged, in.HandoverMissing, in.Routes = false, true, []string{"codex (x)"}
		}), RefreshAdvise, "proxy route is active"},
	}
	for _, c := range cases {
		d := DecideRefresh(c.in)
		if d.Action != c.action {
			t.Errorf("%s: action %s (rule %q), want %s", c.name, d.Action, d.Rule, c.action)
		}
		if c.reason != "" && !strings.Contains(strings.Join(d.Reasons, "; "), c.reason) {
			t.Errorf("%s: reasons %q, want one containing %q", c.name, d.Reasons, c.reason)
		}
	}
}

// TestSplitExecStartInvertsRender pins that `observer service upgrade` keeps
// the arguments `observer service install` baked in.
func TestSplitExecStartInvertsRender(t *testing.T) {
	cases := []struct {
		exe  string
		args []string
	}{
		{"/home/u/.local/bin/observer", nil},
		{"/usr/lib/node_modules/@superbased/observer-linux-x64/bin/observer", []string{"--config", "/home/u/my cfg/config.toml", "--port", "8821"}},
		{"/opt/Observer App/observer", []string{"--recipe", `say "hi"`}},
	}
	for _, c := range cases {
		unit := RenderUnit(UnitOptions{ExecPath: c.exe, Args: c.args, Scope: ScopeUser})
		exe, args, ok := SplitExecStart(ExecStartLine(unit))
		if !ok || exe != c.exe || !reflect.DeepEqual(args, append([]string{}, c.args...)) && !(len(args) == 0 && len(c.args) == 0) {
			t.Errorf("round trip of %q %q: got %q %q ok=%v", c.exe, c.args, exe, args, ok)
		}
	}
	for _, bad := range []string{"", "/bin/observer", "/bin/observer serve", `"/bin/observer start`} {
		if _, _, ok := SplitExecStart(bad); ok {
			t.Errorf("SplitExecStart(%q) accepted", bad)
		}
	}
}
