package config

import "testing"

// TestLiveRunUpdatePolicyPin pins the live_run_update_policy pin row (lane
// SBX-UPD): a DirFree pin, so the org may set either value in either
// direction, the default is defer, and a value outside the closed set is
// skipped rather than applied (and refused by Validate when written).
func TestLiveRunUpdatePolicyPin(t *testing.T) {
	if got := Default().Terminal.Sandbox.LiveRunUpdatePolicy; got != "defer" {
		t.Fatalf("default = %q, want defer", got)
	}
	for _, v := range []string{"ask_immediately", "defer"} {
		cfg := Default()
		cfg.Terminal.Sandbox.LiveRunUpdatePolicy = map[string]string{"defer": "ask_immediately", "ask_immediately": "defer"}[v]
		got, out := ApplyGovernancePinsTo(cfg, map[string]any{"terminal.sandbox.live_run_update_policy": v})
		if got.Terminal.Sandbox.LiveRunUpdatePolicy != v || len(out.Skipped) != 0 {
			t.Fatalf("pin %q: value %q, skipped %v", v, got.Terminal.Sandbox.LiveRunUpdatePolicy, out.Skipped)
		}
	}
	got, out := ApplyGovernancePinsTo(Default(), map[string]any{"terminal.sandbox.live_run_update_policy": "end_now"})
	if got.Terminal.Sandbox.LiveRunUpdatePolicy != "defer" || len(out.Skipped) == 0 {
		t.Fatalf("an out-of-set pin applied: %q (skipped %v)", got.Terminal.Sandbox.LiveRunUpdatePolicy, out.Skipped)
	}
	bad := Default()
	bad.Terminal.Sandbox.LiveRunUpdatePolicy = "end_now"
	if err := validateTerminalSandbox(bad.Terminal.Sandbox); err == nil {
		t.Fatal("Validate accepted an unknown live_run_update_policy")
	}
}

// TestSeatbeltDriverKey pins [terminal.sandbox.seatbelt].driver (lane
// SBX-UPD, plan seatbelt_driver): the default is empty (sandbox-exec), both
// drivers validate and nothing else does, and the org pin can hold a node
// on sandbox-exec but never force the unbuilt fallback.
func TestSeatbeltDriverKey(t *testing.T) {
	c := Default()
	if c.Terminal.Sandbox.Seatbelt.Driver != "" {
		t.Fatalf("default driver = %q", c.Terminal.Sandbox.Seatbelt.Driver)
	}
	for _, v := range []string{"", "sandbox-exec", "mxc-exec-mac"} {
		c.Terminal.Sandbox.Seatbelt.Driver = v
		if err := validateTerminalSandbox(c.Terminal.Sandbox); err != nil {
			t.Fatalf("%q refused: %v", v, err)
		}
	}
	c.Terminal.Sandbox.Seatbelt.Driver = "sandbox-run"
	if err := validateTerminalSandbox(c.Terminal.Sandbox); err == nil {
		t.Fatal("an unknown driver validated")
	}
	local := Default()
	local.Terminal.Sandbox.Seatbelt.Driver = "mxc-exec-mac"
	got, _ := ApplyGovernancePinsTo(local, map[string]any{"terminal.sandbox.seatbelt.driver": "sandbox-exec"})
	if got.Terminal.Sandbox.Seatbelt.Driver != "sandbox-exec" {
		t.Fatalf("the org could not hold the node on sandbox-exec: %q", got.Terminal.Sandbox.Seatbelt.Driver)
	}
	got, out := ApplyGovernancePinsTo(Default(), map[string]any{"terminal.sandbox.seatbelt.driver": "mxc-exec-mac"})
	if got.Terminal.Sandbox.Seatbelt.Driver == "mxc-exec-mac" || len(out.Skipped) == 0 {
		t.Fatalf("the org forced the fallback driver: %q (skipped %v)", got.Terminal.Sandbox.Seatbelt.Driver, out.Skipped)
	}
}
