package config

import (
	"reflect"
	"strings"
	"testing"
)

// TestGovernanceLowerIntKeepsShippedResults pins GovernanceLowerInt, which now
// delegates to postureop.LowerInt, to the results it always gave (roadmap
// F0-8: no PinnableKeys row and no overlay result changes).
func TestGovernanceLowerIntKeepsShippedResults(t *testing.T) {
	for _, r := range []struct{ local, org, want int64 }{
		{0, 30, 30},     // unset local takes the ceiling
		{600, 60, 60},   // a slower node is lowered
		{45, 60, 45},    // a faster node keeps its own
		{60, 60, 60},    // equal
		{45, 0, 45},     // no directive
		{45, -1, 45},    // a negative org value is no directive
		{-5, 60, 60},    // a negative local is unset
		{3600, 30, 30},  // the row's bounds
		{30, 3600, 30},  // never raised
		{120, 300, 120}, // never raised
	} {
		if got := GovernanceLowerInt(r.local, r.org); got != r.want {
			t.Errorf("GovernanceLowerInt(%d,%d)=%d want %d", r.local, r.org, got, r.want)
		}
	}
}

// TestGovernanceMergeDirections walks governanceMerge over synthetic rows of
// every direction: the same postureop operator the accept path checks, so a
// pin that passed accept produces the same value at load. Retention is
// raise-only, so a local 0 (keep forever) survives an org 30.
func TestGovernanceMergeDirections(t *testing.T) {
	type fields struct {
		N    int64
		List []string
		B    bool
	}
	cases := []struct {
		name  string
		dir   string
		kind  string
		field string
		local any
		org   any
		want  any
		skip  bool
	}{
		{"free replaces", governanceDirFree, "bool", "B", false, true, true, false},
		{"restrictive replaces", governanceDirRestrictiveOnly, "bool", "B", true, false, false, false},
		{"lowering keeps a lower local", governanceDirLoweringOnly, "int", "N", int64(45), int64(60), int64(45), false},
		{"lowering lowers", governanceDirLoweringOnly, "int", "N", int64(600), int64(60), int64(60), false},
		{"raising raises", "raising_only", "int", "N", int64(2), int64(3), int64(3), false},
		{"raising keeps a higher local", "raising_only", "int", "N", int64(5), int64(3), int64(5), false},
		{"retention: local forever survives org 30", "retention", "int", "N", int64(0), int64(30), int64(0), false},
		{"retention: org lengthens", "retention", "int", "N", int64(7), int64(30), int64(30), false},
		{"retention: org never shortens", "retention", "int", "N", int64(30), int64(7), int64(30), false},
		{"retention: org forever", "retention", "int", "N", int64(30), int64(0), int64(0), false},
		{"ordered filter", "ordered_filter", "string_list", "List", []string{"a", "b", "c"}, []string{"c", "a"}, []string{"a", "c"}, false},
		{"intersection", "set_intersection", "string_list", "List", []string{"a", "b"}, []string{"b", "z"}, []string{"b"}, false},
		{"empty intersection skips", "set_intersection", "string_list", "List", []string{"a"}, []string{"z"}, nil, true},
		{"empty local reads any", "set_intersection", "string_list", "List", []string(nil), []string{"z"}, []string{"z"}, false},
		{"mask adds", "additive_mask", "string_list", "List", []string{"/x"}, []string{"/y"}, []string{"/x", "/y"}, false},
		{"unknown direction skips", "narrowing_list", "string_list", "List", []string{"a"}, []string{"a"}, nil, true},
		{"int direction on a list field skips", "retention", "int", "List", []string{"a"}, int64(3), nil, true},
	}
	for _, c := range cases {
		var f fields
		fv := reflect.ValueOf(&f).Elem().FieldByName(c.field)
		fv.Set(reflect.ValueOf(c.local))
		got, why := governanceMerge(governancePinnableKey{Key: "k", Kind: c.kind, Direction: c.dir}, fv, c.org, &Config{})
		if c.skip != (why != "") {
			t.Errorf("%s: skip reason %q, want skip=%v", c.name, why, c.skip)
			continue
		}
		if !c.skip && !governanceValuesEqual(got, c.want) {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// TestPolicyFamilyErrorNamesEveryFamily: the unsupported-family errors are
// built from the allow-list (they omitted node.components before roadmap
// F0-10), and both module families are accepted.
func TestPolicyFamilyErrorNamesEveryFamily(t *testing.T) {
	err := validateOrgClientPolicy(OrgClientPolicyConfig{AcceptFamilies: []string{"nope.family"}})
	if err == nil {
		t.Fatal("an unknown family must be refused")
	}
	for f := range policyResourceSupportedFamilies {
		if !strings.Contains(err.Error(), f) {
			t.Errorf("the error omits %q: %v", f, err)
		}
	}
	ok := OrgClientPolicyConfig{
		AcceptFamilies:      []string{"security.scanning", "terminals.isolation"},
		PreauthorizeEnforce: []string{"terminals.isolation"},
	}
	if err := validateOrgClientPolicy(ok); err != nil {
		t.Fatalf("both module families must be accepted: %v", err)
	}
}
