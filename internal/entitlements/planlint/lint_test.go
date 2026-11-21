package planlint

import (
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

// TestPlanLiterals pins the contexts the lint reads: one row per context.
func TestPlanLiterals(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		src  string
		want []string
	}{
		{name: "distinctive spelling anywhere", src: `x := "personal-pro"; _ = x`, want: []string{"personal-pro"}},
		{name: "compared with a plan field", src: `var a struct{ Plan string }; _ = a.Plan == "team"`, want: []string{"team"}},
		{name: "compared on the left", src: `var tier string; _ = "Business" != tier`, want: []string{"Business"}},
		{name: "switched on a tier", src: "var tier string\nswitch tier {\ncase \"business\", \"dedicated\":\n}", want: []string{"business", "dedicated"}},
		{name: "team as a scope is not a plan", src: `var scope string; _ = scope == "team"`},
		{name: "free as a rate is not a plan", src: `var rate string; _ = rate == "free"`},
		{name: "free compared with a plan is", src: `var planName string; _ = planName == "free"`, want: []string{"free"}},
		{name: "a lapsed floor name anywhere", src: `_ = "team_lapsed"`, want: []string{"team_lapsed"}},
		{name: "not a plan word", src: `_ = "teams"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "x.go", "package x\n\nfunc F() {\n"+tc.src+"\n}\n", 0)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			var got []string
			for _, lit := range PlanLiterals(f) {
				v, _ := strconv.Unquote(lit.Value)
				got = append(got, v)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %q, want %q", got, tc.want)
				}
			}
		})
	}
}
