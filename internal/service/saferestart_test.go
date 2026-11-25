package service

import (
	"strings"
	"testing"
)

// TestDecideRestartRows: one case per restartRules row, plus the route-hold
// flag on every row that restarts a running proxy.
func TestDecideRestartRows(t *testing.T) {
	cases := []struct {
		name      string
		in        RestartInputs
		mechanism RestartMechanism
		rule      string
		hold      bool
		startOnly bool
		handover  bool
	}{
		{
			name:      "a dashboard terminal runs the command",
			in:        RestartInputs{Manager: ManagerSystemd, UnitActive: true, ProxyServing: true, DaemonChild: true},
			mechanism: RestartRefuse, rule: "daemon launched this shell",
		},
		{
			name:      "a dashboard terminal runs the command, even with a hand-over",
			in:        RestartInputs{Manager: ManagerNone, DashboardAnswers: true, ProxyServing: true, InPlaceSupported: true, ListenerHandover: true, DaemonChild: true},
			mechanism: RestartRefuse, rule: "daemon launched this shell",
		},
		{
			name:      "the daemon hands its proxy over in place under systemd",
			in:        RestartInputs{Manager: ManagerSystemd, UnitInstalled: true, UnitActive: true, DashboardAnswers: true, ProxyServing: true, InPlaceSupported: true, ListenerHandover: true, ProxyExpected: true},
			mechanism: RestartInPlace, rule: "running, hands its proxy over in place", handover: true,
		},
		{
			name:      "a hand-over needs no organization answer (it takes no route off)",
			in:        RestartInputs{Manager: ManagerNone, DashboardAnswers: true, ProxyServing: true, InPlaceSupported: true, ListenerHandover: true, OrgMaintainsRoutes: true, OrgUnknown: true},
			mechanism: RestartInPlace, rule: "running, hands its proxy over in place", handover: true,
		},
		{
			name:      "a hand-over on an OS without execve is no hand-over",
			in:        RestartInputs{Manager: ManagerNone, DashboardAnswers: true, ProxyServing: true, ListenerHandover: true},
			mechanism: RestartRefuse, rule: "running, cannot restart in place",
		},
		{
			name:      "the daemon-child marker with no daemon is no refusal",
			in:        RestartInputs{Manager: ManagerSystemd, UnitInstalled: true, DaemonChild: true},
			mechanism: RestartViaSystemd, rule: "systemd unit stopped", startOnly: true,
		},
		{
			name:      "the organization maintains the routes",
			in:        RestartInputs{Manager: ManagerSystemd, UnitActive: true, ProxyServing: true, OrgMaintainsRoutes: true},
			mechanism: RestartRefuse, rule: "organization maintains routes",
		},
		{
			name:      "the organization maintains the routes, --keep-routes",
			in:        RestartInputs{Manager: ManagerSystemd, UnitActive: true, ProxyServing: true, OrgMaintainsRoutes: true, KeepRoutes: true},
			mechanism: RestartViaSystemd, rule: "systemd runs it",
		},
		{
			name:      "the organization's route posture could not be read",
			in:        RestartInputs{Manager: ManagerSystemd, UnitActive: true, ProxyServing: true, OrgUnknown: true},
			mechanism: RestartRefuse, rule: "organization route posture unreadable",
		},
		{
			name:      "the organization's route posture could not be read, --keep-routes",
			in:        RestartInputs{Manager: ManagerSystemd, UnitActive: true, ProxyServing: true, OrgUnknown: true, KeepRoutes: true},
			mechanism: RestartViaSystemd, rule: "systemd runs it",
		},
		{
			name:      "the dashboard answers but not the proxy at the resolved port",
			in:        RestartInputs{Manager: ManagerSystemd, UnitActive: true, DashboardAnswers: true, ProxyExpected: true},
			mechanism: RestartRefuse, rule: "proxy not at the resolved port",
		},
		{
			name:      "the dashboard answers and no proxy is configured",
			in:        RestartInputs{Manager: ManagerSystemd, UnitActive: true, DashboardAnswers: true},
			mechanism: RestartViaSystemd, rule: "systemd runs it",
		},
		{
			name:      "systemd runs it",
			in:        RestartInputs{Manager: ManagerSystemd, UnitInstalled: true, UnitActive: true, ProxyServing: true, DashboardAnswers: true, ProxyExpected: true},
			mechanism: RestartViaSystemd, rule: "systemd runs it", hold: true,
		},
		{
			name:      "systemd runs it with no proxy (minimal edition)",
			in:        RestartInputs{Manager: ManagerSystemd, UnitInstalled: true, UnitActive: true},
			mechanism: RestartViaSystemd, rule: "systemd runs it",
		},
		{
			name:      "launchd runs it",
			in:        RestartInputs{Manager: ManagerLaunchd, UnitInstalled: true, UnitActive: true, ProxyServing: true},
			mechanism: RestartViaLaunchd, rule: "launchd runs it", hold: true,
		},
		{
			name:      "no manager, the daemon restarts in place",
			in:        RestartInputs{Manager: ManagerNone, DashboardAnswers: true, ProxyServing: true, InPlaceSupported: true},
			mechanism: RestartInPlace, rule: "running, restarts in place", hold: true,
		},
		{
			name:      "a foreground daemon beside a stopped unit restarts in place",
			in:        RestartInputs{Manager: ManagerSystemd, UnitInstalled: true, DashboardAnswers: true, ProxyServing: true, InPlaceSupported: true},
			mechanism: RestartInPlace, rule: "running, restarts in place", hold: true,
		},
		{
			name:      "in place with --keep-routes",
			in:        RestartInputs{Manager: ManagerNone, DashboardAnswers: true, ProxyServing: true, InPlaceSupported: true, KeepRoutes: true},
			mechanism: RestartInPlace, rule: "running, restarts in place",
		},
		{
			name:      "no manager, no in-place restart (native Windows)",
			in:        RestartInputs{Manager: ManagerNone, DashboardAnswers: true, ProxyServing: true},
			mechanism: RestartRefuse, rule: "running, cannot restart in place",
		},
		{
			name:      "a proxy with no dashboard and no manager",
			in:        RestartInputs{Manager: ManagerNone, ProxyServing: true, InPlaceSupported: true},
			mechanism: RestartRefuse, rule: "proxy without a dashboard",
		},
		{
			name:      "launchd agent installed, not running",
			in:        RestartInputs{Manager: ManagerLaunchd, UnitInstalled: true},
			mechanism: RestartViaLaunchd, rule: "launchd agent stopped", startOnly: true,
		},
		{
			name:      "nothing installed, nothing running",
			in:        RestartInputs{Manager: ManagerSystemd},
			mechanism: RestartNothing, rule: "nothing running",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := DecideRestart(c.in)
			if p.Mechanism != c.mechanism || p.Rule != c.rule || p.HoldRoutes != c.hold || p.StartOnly != c.startOnly || p.Handover != c.handover {
				t.Fatalf("DecideRestart = %+v, want mechanism %s rule %q hold %v startOnly %v handover %v", p, c.mechanism, c.rule, c.hold, c.startOnly, c.handover)
			}
			if p.Handover && p.HoldRoutes {
				t.Fatal("a hand-over never takes a route off")
			}
			if p.Reason == "" {
				t.Fatal("every plan carries its reason")
			}
		})
	}
}

// TestEveryRestartRuleIsCovered: a row added to the table needs a case
// above (the rule names are the contract).
func TestEveryRestartRuleIsCovered(t *testing.T) {
	covered := map[string]bool{
		"daemon launched this shell": true, "organization maintains routes": true, "systemd runs it": true,
		"running, hands its proxy over in place": true,
		"organization route posture unreadable":  true, "proxy not at the resolved port": true,
		"launchd runs it": true, "running, restarts in place": true, "running, cannot restart in place": true,
		"proxy without a dashboard": true, "systemd unit stopped": true, "launchd agent stopped": true, "nothing running": true,
	}
	for _, r := range restartRules {
		if !covered[r.name] {
			t.Errorf("restart rule %q has no test case", r.name)
		}
	}
}

// TestNoInPlaceRefusalGivesAdviceThatWorks (finding 6): Windows never has a
// service manager `service restart` drives, so the refusal must not send the
// developer to `observer setup autostart on` (after which it refuses again);
// it says to quit and start the daemon between AI turns.
func TestNoInPlaceRefusalGivesAdviceThatWorks(t *testing.T) {
	p := DecideRestart(RestartInputs{Manager: ManagerNone, DashboardAnswers: true, ProxyServing: true})
	if p.Rule != "running, cannot restart in place" {
		t.Fatalf("rule = %q", p.Rule)
	}
	if strings.Contains(p.Reason, "autostart") {
		t.Fatalf("the refusal still suggests autostart: %s", p.Reason)
	}
	if !strings.Contains(p.Reason, "observer start") {
		t.Fatalf("the refusal does not say how to restart: %s", p.Reason)
	}
}
