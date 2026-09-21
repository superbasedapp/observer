package nodegov

import "testing"

// reportable_test.go — Track C item 3
// (docs/plans/org-guardrail-control-wave-2026-09-21.md). These tests pin the
// CONTENT FLOOR of the effective-pin report: it is structural, not a promise,
// so it is asserted here against the vocabulary table itself rather than at
// the wire.

// TestOnlyBoolAndClosedEnumKeysAreReportable is the floor. An int is a
// threshold the developer chose and a string_list is paths or action names;
// neither may ever cross the org wire through this field, and the only thing
// standing between them and it is this predicate.
func TestOnlyBoolAndClosedEnumKeysAreReportable(t *testing.T) {
	for _, k := range PinnableKeys {
		got := k.ReportableValue()
		var want bool
		switch k.Kind {
		case "bool":
			want = true
		case "string":
			want = len(k.Enum) > 0
		default:
			want = false
		}
		if got != want {
			t.Errorf("%s (kind %q, enum %v): ReportableValue = %v, want %v", k.Key, k.Kind, k.Enum, got, want)
		}
		if got && k.Kind != "bool" && len(k.Enum) == 0 {
			t.Errorf("%s is reportable with an OPEN string value — that is a content leak", k.Key)
		}
		if k.Kind == "int" || k.Kind == "string_list" {
			if got {
				t.Errorf("%s is kind %q and must never be reportable", k.Key, k.Kind)
			}
		}
	}
}

// TestNormalizeReportedValue is the value table, including the one case an
// admin can actually produce by hand-editing a node's config: a value outside
// the key's own enum, which must collapse to the fixed "other" token rather
// than travelling.
func TestNormalizeReportedValue(t *testing.T) {
	boolKey := PinnableKey{Key: "guard.enabled", Kind: "bool"}
	enumKey := PinnableKey{Key: "guard.mode", Kind: "string", Enum: []any{"off", "observe", "enforce"}}
	intKey := PinnableKey{Key: "x.y", Kind: "int"}
	listKey := PinnableKey{Key: "x.z", Kind: "string_list"}
	openString := PinnableKey{Key: "x.s", Kind: "string"}

	cases := []struct {
		name   string
		key    PinnableKey
		in     any
		want   string
		wantOK bool
	}{
		{"bool true", boolKey, true, "true", true},
		{"bool false", boolKey, false, "false", true},
		{"bool given a string", boolKey, "true", "", false},
		{"enum member", enumKey, "enforce", "enforce", true},
		{"enum value outside the set collapses to other", enumKey, "strict", ReportedValueOther, true},
		{"enum given a bool", enumKey, true, "", false},
		{"int is never reported", intKey, 42, "", false},
		{"string_list is never reported", listKey, []string{"a"}, "", false},
		{"open string is never reported", openString, "/home/dev/secret", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tc.key.NormalizeReportedValue(tc.in)
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("NormalizeReportedValue(%v) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// TestReportedValueAllowedMirrorsTheProducer pins the two halves together:
// every value NormalizeReportedValue can PRODUCE must be one the server-side
// validator ACCEPTS, or a truthful node would have its whole ack report
// rejected.
func TestReportedValueAllowedMirrorsTheProducer(t *testing.T) {
	for _, k := range ReportableKeys() {
		var produced []string
		switch k.Kind {
		case "bool":
			produced = []string{"true", "false"}
		case "string":
			for _, e := range k.Enum {
				if s, ok := e.(string); ok {
					produced = append(produced, s)
				}
			}
			produced = append(produced, ReportedValueOther)
		}
		for _, v := range produced {
			if !ReportedValueAllowed(k.Key, v) {
				t.Errorf("%s can report %q but the validator refuses it", k.Key, v)
			}
		}
	}
	// And the converse: an unknown key, and a value outside a known key's
	// vocabulary, are both refused.
	if ReportedValueAllowed("not.a.pinnable.key", "true") {
		t.Error("the validator accepted an unknown key")
	}
	if ReportedValueAllowed("guard.enabled", "yes") {
		t.Error("the validator accepted a bool value outside {true,false}")
	}
	if ReportedValueAllowed("guard.mode", "strict") {
		t.Error("the validator accepted an enum value outside the key's set (it must arrive as \"other\")")
	}
	// A key that exists but is NOT reportable must be refused outright.
	for _, k := range PinnableKeys {
		if !k.ReportableValue() && ReportedValueAllowed(k.Key, "true") {
			t.Errorf("the validator accepted %q, which is not a reportable key", k.Key)
		}
	}
}
