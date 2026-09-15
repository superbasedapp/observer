package nodegov

import "testing"

// TestRoutingEnabledIsPinnableRoutingModeIsNot is the W5 named change
// (docs/plans/org-observer-fundamentals-fix-plan-2026-09-13.md R4):
// routing.enabled moved OUT of BootstrapEnvelopeKeys into PinnableKeys
// (DirFree, the same shape as guard.budget.from_org), while routing.mode
// stays excluded — its value still rides the separate signed org
// routing-policy body, honored only for a managed node holding
// enforce.routing (govern.Effective.GrantsRoutingEnforcement). This test
// pins the split so a future edit that quietly reverts either half, or
// re-couples the two keys, fails loud.
func TestRoutingEnabledIsPinnableRoutingModeIsNot(t *testing.T) {
	row, ok := LookupPinnableKey("routing.enabled")
	if !ok {
		t.Fatal("routing.enabled is not a pinnable key — the org cannot turn routing on for a managed node")
	}
	if row.Kind != "bool" {
		t.Errorf("Kind = %q, want %q", row.Kind, "bool")
	}
	if row.Direction != DirFree {
		t.Errorf("Direction = %v, want %v (both true and false are legitimate fleet postures)", row.Direction, DirFree)
	}
	if row.Enum != nil {
		t.Errorf("Enum = %v, want nil for a bool key", row.Enum)
	}
	if row.Label == "" {
		t.Error("Label is empty — the admin console would render a blank picker row")
	}

	if IsPinnableKey("routing.mode") {
		t.Fatal("routing.mode became pinnable — its value must keep riding the signed org routing-policy body, not a settings pin")
	}

	foundEnabled, foundMode := false, false
	for _, k := range BootstrapEnvelopeKeys {
		if k == "routing.enabled" {
			foundEnabled = true
		}
		if k == "routing.mode" {
			foundMode = true
		}
	}
	if foundEnabled {
		t.Error("routing.enabled is still in BootstrapEnvelopeKeys — it should have moved to PinnableKeys")
	}
	if !foundMode {
		t.Error("routing.mode is no longer in BootstrapEnvelopeKeys — its exclusion from the settings-pin vocabulary must stay explicit")
	}
}

// TestCompileBody_RoutingEnabled is the publish/accept round trip: an org may
// pin routing.enabled either true or false (DirFree), mirroring
// TestCompileBody_GuardBudgetPosture's from_org case.
func TestCompileBody_RoutingEnabled(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want bool
	}{
		{"true compiles", `{"schema":2,"pinned":{"routing.enabled":true}}`, true},
		{"false compiles", `{"schema":2,"pinned":{"routing.enabled":false}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, _, err := CompileBody([]byte(tc.raw), schema2Max)
			if err != nil {
				t.Fatalf("CompileBody: %v", err)
			}
			if got, ok := spec.Pinned["routing.enabled"].(bool); !ok || got != tc.want {
				t.Fatalf("spec.Pinned[\"routing.enabled\"] = %#v, want %v", spec.Pinned["routing.enabled"], tc.want)
			}
		})
	}

	t.Run("routing.mode is refused", func(t *testing.T) {
		if _, _, err := CompileBody([]byte(`{"schema":2,"pinned":{"routing.mode":"enforce"}}`), schema2Max); err == nil {
			t.Fatal("the compiler accepted a routing.mode settings pin — mode must only travel on the signed org routing-policy body")
		}
	})
}
