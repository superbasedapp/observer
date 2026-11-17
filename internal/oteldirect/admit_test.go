package oteldirect

import (
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// knownDropped is every envelope family an OTel-direct batch drops, named so
// a NEW envelope field fails TestEveryEnvelopeFamilyClassified until someone
// decides whether an exporter may land it.
var knownDropped = map[string]bool{
	"update_posture": true, "token_usage": true, "deletions": true, "session_manifests": true,
	"routing_summaries": true, "cache_summaries": true, "codeintel_summaries": true,
	"process_summaries": true, "session_verbosity": true, "session_loc": true, "loc_days": true,
	"session_quality": true, "commit_ownership": true, "delivery_days": true, "pull_requests": true,
	"session_cache": true, "session_cache_events": true, "session_processes": true,
	"session_process_rollups": true, "session_process_capture_stats": true,
	"session_network_events": true, "session_task_items": true, "session_task_transitions": true,
	"session_tool_accounts": true, "session_hook_activity": true,
	"advisor_suggestions": true, "project_patterns": true,
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
	sets := []map[string]bool{admittedFamilies, keptScalars, clearedScalars, knownDropped}
	seen := map[string]bool{}
	for i := 0; i < typ.NumField(); i++ {
		name := jsonName(typ.Field(i))
		seen[name] = true
		n := 0
		for _, set := range sets {
			if set[name] {
				n++
			}
		}
		if n != 1 {
			t.Errorf("envelope field %q is classified %d times; add it to exactly one of admittedFamilies, keptScalars, clearedScalars (admit.go) or knownDropped (this test)", name, n)
		}
	}
	for _, set := range sets {
		for name := range set {
			if !seen[name] {
				t.Errorf("classification names %q, which is not an envelope field", name)
			}
		}
	}
}

// fullEnvelope sets every slice field to one zero row and every pointer to a
// zero value.
func fullEnvelope() orgcontract.PushEnvelope {
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
	env.AgentVersion = "otel-direct/1"
	env.CursorFrom, env.CursorTo = 4, 9
	env.MachineIdentity = "spoofed"
	env.SourceNodeKey = "jkt:spoofed"
	return env
}

func TestAdmit(t *testing.T) {
	env := fullEnvelope()
	got := Admit(env)
	if got.Rows != len(admittedFamilies) {
		t.Fatalf("rows = %d, want %d", got.Rows, len(admittedFamilies))
	}
	if got.DroppedTotal() != len(knownDropped) || len(got.Dropped) != len(knownDropped) {
		t.Fatalf("dropped = %d families / %d rows, want %d", len(got.Dropped), got.DroppedTotal(), len(knownDropped))
	}
	for name := range knownDropped {
		if got.Dropped[name] != 1 {
			t.Errorf("dropped[%q] = %d", name, got.Dropped[name])
		}
	}
	e := got.Envelope
	if e.AgentVersion != "otel-direct/1" || e.MachineIdentity != "" || e.SourceNodeKey != "" || e.CursorFrom != 0 || e.CursorTo != 0 {
		t.Fatalf("scalars = %q %q %q %d %d", e.AgentVersion, e.MachineIdentity, e.SourceNodeKey, e.CursorFrom, e.CursorTo)
	}
	if len(e.Sessions) != 1 || len(e.Actions) != 1 || len(e.APITurns) != 1 || len(e.OTelContent) != 1 ||
		len(e.TokenUsage) != 0 || e.UpdatePosture != nil || len(e.GuardEvents) != 0 {
		t.Fatalf("admitted envelope = %+v", e)
	}
	// Admit never mutates its input.
	got.Envelope.Sessions[0].ID = "changed"
	if env.Sessions[0].ID != "" {
		t.Fatal("Admit shares a slice with its input")
	}
	if want := []string{"actions", "api_turns", "otel_content", "sessions"}; !reflect.DeepEqual(AdmittedFamilies(), want) {
		t.Fatalf("AdmittedFamilies = %v", AdmittedFamilies())
	}
	// An empty envelope drops nothing.
	if a := Admit(orgcontract.PushEnvelope{}); a.Rows != 0 || a.DroppedTotal() != 0 {
		t.Fatalf("empty admit = %+v", a)
	}
}
