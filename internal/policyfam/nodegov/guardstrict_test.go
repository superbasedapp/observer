package nodegov

import "testing"

// TestGuardStrictPinnableRow closes HG11: it dedicated-pins guard.strict's
// row shape and schema-2 publish/accept round trip, on top of the generic,
// structurally-generic coverage every PinnableKeys row already gets from
// TestEveryPinnableKeyResolvesInConfig / TestVocabularyIsComplete /
// TestEveryFeatureExpandsToAPinnableKey. guard.strict is DirFree (a
// fail-posture choice, not a privacy-sharing direction — see the doc comment
// on its PinnableKeys row) so, unlike observer.secrets.enable_scrubbing, an
// org body may push it either true or false.
func TestGuardStrictPinnableRow(t *testing.T) {
	row, ok := LookupPinnableKey("guard.strict")
	if !ok {
		t.Fatal("guard.strict is not registered as a pinnable key")
	}
	if row.Kind != "bool" {
		t.Errorf("Kind = %q, want %q", row.Kind, "bool")
	}
	if row.Direction != DirFree {
		t.Errorf("Direction = %v, want DirFree — guard.strict is a fail-posture choice, not a safe/unsafe privacy pair", row.Direction)
	}
	if row.Enum != nil {
		t.Errorf("Enum = %v, want nil for a bool key", row.Enum)
	}
	if row.Label == "" {
		t.Error("Label is empty")
	}
	if !IsPinnableKey("guard.strict") {
		t.Error("IsPinnableKey(\"guard.strict\") = false, want true")
	}
}

// TestCompileBody_GuardStrict mirrors the existing guard.enabled/guard.mode
// compile-accept idiom in TestCompileSchema2Accepted: a schema-2 body naming
// guard.strict must compile, in both boolean directions, exactly like any
// other DirFree bool key — there is no restrictive-only or enum constraint
// to trip.
func TestCompileBody_GuardStrict(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{name: "guard.strict:true compiles", raw: `{"schema":2,"pinned":{"guard.strict":true}}`, want: true},
		{name: "guard.strict:false compiles", raw: `{"schema":2,"pinned":{"guard.strict":false}}`, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, _, err := CompileBody([]byte(tc.raw), schema2Max)
			if err != nil {
				t.Fatalf("CompileBody: %v", err)
			}
			got, ok := spec.Pinned["guard.strict"].(bool)
			if !ok {
				t.Fatalf("spec.Pinned[\"guard.strict\"] = %#v, want a bool", spec.Pinned["guard.strict"])
			}
			if got != tc.want {
				t.Errorf("spec.Pinned[\"guard.strict\"] = %v, want %v", got, tc.want)
			}
		})
	}

	// A body pinning guard.strict alongside its guard.enabled/guard.mode
	// siblings must also compile — the three keys are independent, not
	// mutually exclusive.
	t.Run("guard.strict alongside its guard.enabled/guard.mode siblings", func(t *testing.T) {
		spec, _, err := CompileBody([]byte(`{"schema":2,"pinned":{"guard.enabled":true,"guard.mode":"enforce","guard.strict":true}}`), schema2Max)
		if err != nil {
			t.Fatalf("CompileBody: %v", err)
		}
		if spec.Pinned["guard.enabled"] != true || spec.Pinned["guard.mode"] != "enforce" || spec.Pinned["guard.strict"] != true {
			t.Fatalf("pinned = %+v", spec.Pinned)
		}
	})
}
