package sandboxadopt

import (
	"strings"
	"testing"
)

// samePolicy is a kept plan equal to today's.
func samePolicy() PolicyFacts {
	return PolicyFacts{
		Recorded: true, TodayRead: true, Backend: "oci-runc", Listed: true,
		KeptTier: "none", TodayTier: "none", KeptTierStrictness: 3, TodayTierStrictness: 3,
	}
}

// TestCheckPolicyRows: one case per row of the policy table, plus the same
// and the stricter plan, which pass.
func TestCheckPolicyRows(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		edit func(*PolicyFacts)
		want string // a word of the reason; "" passes
	}{
		{"same plan passes", func(*PolicyFacts) {}, ""},
		{"stricter tier passes", func(f *PolicyFacts) { f.TodayTier, f.TodayTierStrictness = "internet", 1 }, ""},
		{"recorded", func(f *PolicyFacts) { f.Recorded = false }, "not kept"},
		{"today", func(f *PolicyFacts) { f.TodayRead, f.TodayErr = false, "bad toml" }, "bad toml"},
		{"listed", func(f *PolicyFacts) { f.Listed = false }, "no longer in"},
		{"min_isolation", func(f *PolicyFacts) { f.BelowMinIsolation = "hw_vm" }, "min_isolation"},
		{"org_floor", func(f *PolicyFacts) { f.FloorDropped = "org minimum isolation hw_vm" }, "organization floor"},
		{"tier", func(f *PolicyFacts) { f.KeptTier, f.KeptTierStrictness = "internet", 1 }, "wider"},
		{"tier unknown", func(f *PolicyFacts) { f.KeptTierStrictness = -1 }, "wider"},
		{"binds", func(f *PolicyFacts) { f.WidenedBinds = []string{"/data (read-write)"} }, "/data"},
		{"cidrs", func(f *PolicyFacts) { f.WidenedCIDRs = []string{"10.0.0.0/8"} }, "10.0.0.0/8"},
		{"masks", func(f *PolicyFacts) { f.DroppedMasks = []string{"/secret"} }, "/secret"},
		{"tool_config_writes", func(f *PolicyFacts) { f.ToolConfigWritesWidened = true }, "allow_tool_config_writes"},
	}
	for _, tc := range cases {
		f := samePolicy()
		tc.edit(&f)
		r := CheckPolicy(f)
		switch {
		case tc.want == "" && r != nil:
			t.Errorf("%s: refused %v", tc.name, r)
		case tc.want != "" && (r == nil || r.Code != CodePolicyChanged || !strings.Contains(r.Reason, tc.want)):
			t.Errorf("%s: got %v, want policy_changed naming %q", tc.name, r, tc.want)
		}
	}
	if len(policyRules) != 10 {
		t.Fatalf("the policy table has %d rows; add a case for the new one", len(policyRules))
	}
}

// TestWidenedBinds: a read-write bind must stay read-write; a read-only
// one may be in either list.
func TestWidenedBinds(t *testing.T) {
	t.Parallel()
	got := WidenedBinds([]string{"/a", "/b"}, []string{"/c", "/d"}, []string{"/a", "/d"}, []string{"/b"})
	want := []string{"/b (read-write)", "/c (read-only)"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %v, want %v", got, want)
	}
	if m := Missing([]string{"x", "y"}, []string{"y"}); len(m) != 1 || m[0] != "x" {
		t.Fatalf("Missing = %v", m)
	}
}
