package shiptoken

import (
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// knownDropped is every envelope family a ship-token batch drops, named so a
// NEW envelope field fails TestEveryEnvelopeFamilyClassified until someone
// decides whether a sandbox may land it.
var knownDropped = map[string]bool{
	"update_posture": true, "deletions": true, "session_manifests": true,
	"routing_summaries": true, "cache_summaries": true, "codeintel_summaries": true,
	"process_summaries": true, "loc_days": true, "commit_ownership": true,
	"delivery_days": true, "pull_requests": true, "session_processes": true,
	"session_process_rollups": true, "session_process_capture_stats": true,
	"session_network_events": true, "advisor_suggestions": true, "project_patterns": true,
	"benchmark_runs": true, "benchmark_attempts": true, "compression_stats": true,
	"routing_dev": true, "codeintel_dev": true, "terminal_runs": true,
	"terminal_commands": true, "remote_audit": true, "guard_pins": true,
	"guard_approvals": true, "terminal_summaries": true, "remote_audit_summaries": true,
	"sandbox_posture": true, "sandbox_capability": true, "sandbox_egress_refusals": true, "security_posture": true,
	"security_findings": true, "ai_change_records": true, "mcp_relay_activity": true,
	"mcp_relay_events": true, "mcp_inventory": true, "routing_details": true,
	"limit_gauges": true, "session_limit_snapshots": true, "guard_events": true,
	"obs_summaries": true, "obs_traces": true, "obs_spans": true, "obs_span_events": true,
	"obs_content": true, "obs_eval_runs": true, "obs_enduser_spend": true,
	"obs_admission_events": true, "obs_admission_policies": true, "obs_eval_items": true,
	"obs_egress_decisions": true, "budget_posture": true, "component_posture": true,
	"agent_config_state": true, "agent_config_inventory": true,
}

func TestEveryEnvelopeFamilyClassified(t *testing.T) {
	typ := reflect.TypeOf(orgcontract.PushEnvelope{})
	seen := map[string]bool{}
	for i := 0; i < typ.NumField(); i++ {
		name := jsonName(typ.Field(i))
		seen[name] = true
		n := 0
		for _, set := range []map[string]bool{admittedFamilies, keptScalars, forcedScalars, knownDropped} {
			if set[name] {
				n++
			}
		}
		if n != 1 {
			t.Errorf("envelope field %q is classified %d times; add it to exactly one of admittedFamilies, keptScalars, forcedScalars (admit.go) or knownDropped (this test)", name, n)
		}
	}
	for _, set := range []map[string]bool{admittedFamilies, keptScalars, forcedScalars, knownDropped} {
		for name := range set {
			if !seen[name] {
				t.Errorf("classification names %q, which is not an envelope field", name)
			}
		}
	}
}

// fullEnvelope sets every slice field to one zero row and every pointer to a
// zero value, so each family is present.
func fullEnvelope(t *testing.T) orgcontract.PushEnvelope {
	t.Helper()
	var env orgcontract.PushEnvelope
	v := reflect.ValueOf(&env).Elem()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		switch f.Kind() {
		case reflect.Slice:
			f.Set(reflect.MakeSlice(f.Type(), 1, 1))
		case reflect.Pointer:
			f.Set(reflect.New(f.Type().Elem()))
		}
	}
	env.AgentVersion = "1.2.3"
	env.CursorFrom, env.CursorTo = 4, 9
	env.MachineIdentity = "spoofed"
	env.SourceNodeKey = "jkt:spoofed"
	return env
}

func TestAdmitKeepsOnlyAdmittedFamilies(t *testing.T) {
	env := fullEnvelope(t)
	env.Sessions[0].ExecutionLocation = models.ExecutionVendorCloud
	got := Admit(env, Binding{UserID: "u1", MachineIdentity: "mach"})

	out := reflect.ValueOf(got.Envelope)
	typ := out.Type()
	for i := 0; i < typ.NumField(); i++ {
		name := jsonName(typ.Field(i))
		n := rowCount(out.Field(i))
		switch {
		case admittedFamilies[name]:
			if n != 1 {
				t.Errorf("admitted %q lost its row", name)
			}
			if got.Dropped[name] != 0 {
				t.Errorf("admitted %q counted as dropped", name)
			}
		case knownDropped[name]:
			if n != 0 {
				t.Errorf("dropped %q still carries rows", name)
			}
			if got.Dropped[name] != 1 {
				t.Errorf("dropped %q counted %d, want 1", name, got.Dropped[name])
			}
		}
	}
	if got.Rows != len(admittedFamilies) {
		t.Errorf("Rows = %d, want %d", got.Rows, len(admittedFamilies))
	}
	if got.DroppedTotal() != len(knownDropped) {
		t.Errorf("DroppedTotal = %d, want %d", got.DroppedTotal(), len(knownDropped))
	}
	e := got.Envelope
	if e.MachineIdentity != "mach" || e.SourceNodeKey != "" {
		t.Errorf("identity not bound: machine %q source key %q", e.MachineIdentity, e.SourceNodeKey)
	}
	if e.AgentVersion != "1.2.3" || e.CursorFrom != 4 || e.CursorTo != 9 {
		t.Errorf("scalars not kept: %+v", e)
	}
	if e.Sessions[0].ExecutionLocation != models.ExecutionVendorCloud || got.Execution[ExecKept] != 1 {
		t.Errorf("execution not kept: %q %v", e.Sessions[0].ExecutionLocation, got.Execution)
	}
}

func TestAdmitDoesNotMutateInput(t *testing.T) {
	env := fullEnvelope(t)
	env.Sessions[0].ExecutionLocation = models.ExecutionLocal
	_ = Admit(env, Binding{})
	if env.Sessions[0].ExecutionLocation != models.ExecutionLocal || env.SourceNodeKey == "" || len(env.Deletions) != 1 {
		t.Fatal("Admit mutated its input")
	}
}

func TestResolveExecution(t *testing.T) {
	for _, tc := range []struct {
		in, landed, outcome string
	}{
		{"", "", ExecUnknown},
		{"  ", "", ExecUnknown},
		{models.ExecutionLocal, "", ExecRefused},
		{models.ExecutionVendorCloud, models.ExecutionVendorCloud, ExecKept},
		{models.ExecutionCustomerWorker, models.ExecutionCustomerWorker, ExecKept},
		{"mars", "", ExecInvalid},
	} {
		landed, outcome := ResolveExecution(tc.in)
		if landed != tc.landed || outcome != tc.outcome {
			t.Errorf("ResolveExecution(%q) = %q %q, want %q %q", tc.in, landed, outcome, tc.landed, tc.outcome)
		}
	}
}

func TestAdmittedFamiliesSorted(t *testing.T) {
	got := AdmittedFamilies()
	if len(got) != len(admittedFamilies) || got[0] != "actions" {
		t.Fatalf("AdmittedFamilies = %v", got)
	}
}
