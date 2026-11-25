package service

import "testing"

// TestDecideStopRoutesRows: one case per stopRoutesRules row (L-168).
func TestDecideStopRoutesRows(t *testing.T) {
	served := StopRoutesInputs{ProxyServed: true, Owner: RouteOwnerNode}
	with := func(f func(*StopRoutesInputs)) StopRoutesInputs {
		in := served
		f(&in)
		return in
	}
	cases := []struct {
		name   string
		in     StopRoutesInputs
		rule   string
		action StopRoutesAction
	}{
		{
			"an update released the listeners", with(func(in *StopRoutesInputs) { in.Event = StopEventUpdateHandover }),
			"update hands the port over", StopRoutesLeave,
		},
		{
			"the restart hands the socket over", with(func(in *StopRoutesInputs) { in.Event = StopEventRestartHandover }),
			"restart hands the port over", StopRoutesLeave,
		},
		{
			"a component failed", with(func(in *StopRoutesInputs) { in.Event = StopEventFailure }),
			"a part of the daemon failed", StopRoutesLeave,
		},
		{
			"the bind failed (another daemon owns the port)", with(func(in *StopRoutesInputs) { in.Event = StopEventStop; in.ProxyServed = false }),
			"this proxy never served", StopRoutesLeave,
		},
		{
			"`observer service stop` took the routes itself", with(func(in *StopRoutesInputs) { in.Event = StopEventStop; in.VerbHolds = true }),
			"a service verb holds the routes", StopRoutesLeave,
		},
		{
			"the organization maintains the routes", with(func(in *StopRoutesInputs) { in.Event = StopEventStop; in.Owner = RouteOwnerOrg }),
			"organization maintains routes", StopRoutesLeave,
		},
		{
			"the organization's posture could not be read", with(func(in *StopRoutesInputs) { in.Event = StopEventStop; in.Owner = RouteOwnerUnknown }),
			"organization route posture unreadable", StopRoutesLeave,
		},
		{
			"an empty owner reads as unknown", with(func(in *StopRoutesInputs) { in.Event = StopEventStop; in.Owner = "" }),
			"organization route posture unreadable", StopRoutesLeave,
		},
		{
			"a deliberate stop", with(func(in *StopRoutesInputs) { in.Event = StopEventStop }),
			"deliberate stop", StopRoutesTakeOff,
		},
		{
			"a restart with no socket to hand over", with(func(in *StopRoutesInputs) { in.Event = StopEventRestart }),
			"restart without a hand-over", StopRoutesTakeOff,
		},
		{
			"an event the table does not know", with(func(in *StopRoutesInputs) { in.Event = "mystery" }),
			"unknown event", StopRoutesLeave,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := DecideStopRoutes(c.in)
			if p.Rule != c.rule || p.Action != c.action {
				t.Fatalf("DecideStopRoutes(%+v) = %+v, want rule %q action %s", c.in, p, c.rule, c.action)
			}
			if p.Reason == "" {
				t.Fatal("every plan carries its reason")
			}
		})
	}
}

// TestEveryStopRoutesRuleIsCovered: a row added to the table needs a case
// above.
func TestEveryStopRoutesRuleIsCovered(t *testing.T) {
	covered := map[string]bool{
		"update hands the port over": true, "restart hands the port over": true, "a part of the daemon failed": true,
		"this proxy never served": true, "a service verb holds the routes": true, "organization maintains routes": true,
		"organization route posture unreadable": true, "deliberate stop": true, "restart without a hand-over": true,
		"unknown event": true,
	}
	for _, r := range stopRoutesRules {
		if !covered[r.name] {
			t.Errorf("stop routes rule %q has no test case", r.name)
		}
	}
}

// TestNoHandOverEventEverTakesRoutesOff: whatever else holds, an event that
// passes the port on (a restart or an update hand-over) leaves the routes.
func TestNoHandOverEventEverTakesRoutesOff(t *testing.T) {
	for _, ev := range []StopEvent{StopEventRestartHandover, StopEventUpdateHandover, StopEventFailure} {
		for _, owner := range []RouteOwner{RouteOwnerNode, RouteOwnerOrg, RouteOwnerUnknown} {
			for _, verb := range []bool{false, true} {
				in := StopRoutesInputs{Event: ev, ProxyServed: true, Owner: owner, VerbHolds: verb}
				if p := DecideStopRoutes(in); p.Action != StopRoutesLeave {
					t.Errorf("DecideStopRoutes(%+v) = %+v, want leave", in, p)
				}
			}
		}
	}
}

func TestStartArgsAndInvocationDigest(t *testing.T) {
	if _, ok := StartArgs([]string{"/bin/observer", "proxy", "start"}); ok {
		t.Fatal("a non-start argv has no start args")
	}
	args, ok := StartArgs([]string{"/bin/observer", "start", "--config", "/c.toml"})
	if !ok || len(args) != 2 || args[0] != "--config" {
		t.Fatalf("StartArgs = %v %v", args, ok)
	}
	unitExe, unitArgs, ok := SplitExecStart("/bin/observer start --config /c.toml")
	if !ok {
		t.Fatal("SplitExecStart")
	}
	if !InvocationsMatch(InvocationDigest("/bin/observer", args), InvocationDigest(unitExe, unitArgs)) {
		t.Fatal("the daemon's argv and the unit's ExecStart of the same command must match")
	}
	for _, other := range [][]string{{"--config", "/other.toml"}, {"--config"}, {"--config /c.toml"}, nil} {
		if InvocationsMatch(InvocationDigest("/bin/observer", args), InvocationDigest("/bin/observer", other)) {
			t.Errorf("args %q matched %q", other, args)
		}
	}
	if InvocationsMatch(InvocationDigest("/bin/observer", args), InvocationDigest("/opt/observer", args)) {
		t.Error("another executable matched")
	}
	if InvocationsMatch(InvocationDigest("", nil), InvocationDigest("", nil)) {
		t.Error("an unknown invocation never matches")
	}
}
