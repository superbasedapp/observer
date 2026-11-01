package secframework

import (
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql", "net/http", "net", "os", "os/exec", "github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/store",
		},
		Reason: "internal/secframework is pure: the caller injects the build and selection facts",
	})
}

// TestMappingNamesOnlyThePlanIDsAndCatalogComponents: exactly the ids
// section 7.8 names, once each, every component in the node catalog.
func TestMappingNamesOnlyThePlanIDsAndCatalogComponents(t *testing.T) {
	want := []string{"ASI02", "ASI04", "ASI05", "LLM03", "AML.T0081", "AML.T0083", "AML.M0029", "AML.M0030"}
	var got []string
	for _, e := range Mapping {
		got = append(got, e.ID)
		if e.Scope == "" || len(e.Groups) == 0 {
			t.Errorf("%s: no scope or groups", e.ID)
		}
		for _, g := range e.Groups {
			if g.What == "" || len(g.AnyOf) == 0 {
				t.Errorf("%s: an empty group", e.ID)
			}
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("ids = %v, want %v", got, want)
	}
	for _, id := range ComponentIDs() {
		if c, ok := components.Get(id); !ok || c.Binary != components.BinaryNode {
			t.Errorf("%s is not a node catalog component", id)
		}
	}
}

func TestStatusTable(t *testing.T) {
	set := func(ids ...string) func(string) bool { return func(id string) bool { return slices.Contains(ids, id) } }
	all := set(ComponentIDs()...)
	none := set()
	cases := []struct {
		name          string
		built, chosen func(string) bool
		id            string
		want          Status
	}{
		{"everything selected", all, all, "ASI04", StatusCovered},
		{"one of two groups", all, set("security.deps"), "LLM03", StatusPartial},
		{"any of a group is enough", all, set("security.deps", "security.scan.osv"), "LLM03", StatusCovered},
		{"built, nothing selected", all, none, "AML.T0081", StatusNotSelected},
		{"not in this build", none, none, "ASI02", StatusNotBuilt},
		{"selected but not built never counts", none, all, "ASI05", StatusNotBuilt},
		{"partly built, built part selected", set("security.trust"), all, "ASI04", StatusPartial},
	}
	for _, tc := range cases {
		var row Row
		for _, r := range Report(Facts{Built: tc.built, Selected: tc.chosen}) {
			if r.ID == tc.id {
				row = r
			}
		}
		if row.Status != tc.want {
			t.Errorf("%s: %s = %s, want %s (%+v)", tc.name, tc.id, row.Status, tc.want, row.Groups)
		}
	}
}

func TestPicker(t *testing.T) {
	if p, ok := ParseFramework("all"); !ok || p != nil {
		t.Fatal("all")
	}
	if p, ok := ParseFramework("MITRE-ATLAS-2026.09"); !ok || len(p) != 1 || p[0] != ATLAS {
		t.Fatal("atlas")
	}
	if _, ok := ParseFramework("nist"); ok {
		t.Fatal("an unknown framework parsed")
	}
	if n := len(Report(Facts{}, OWASPLLM)); n != 1 {
		t.Fatalf("owasp-llm rows = %d", n)
	}
}
