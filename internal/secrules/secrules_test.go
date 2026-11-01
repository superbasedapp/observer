package secrules

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

func TestPureImports(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"os", "os/exec", "net", "net/http", "database/sql", "github.com/fsnotify/fsnotify"},
		Custom: func(_, p string) string {
			if strings.HasPrefix(p, "github.com/marmutapp/superbased-observer/") && !pureDeps[p] {
				return "secrules imports internal/policy and the pure detection packages only"
			}
			return ""
		},
		Reason: "security pillar plan section 4.7: pure rule tables",
	})
}

// pureDeps are the pure packages the rule tables may read facts through.
var pureDeps = map[string]bool{
	"github.com/marmutapp/superbased-observer/internal/policy":    true,
	"github.com/marmutapp/superbased-observer/internal/models":    true,
	"github.com/marmutapp/superbased-observer/internal/secdetect": true,
	"github.com/marmutapp/superbased-observer/internal/sectrust":  true,
	// The commit gate's decision table (lane SEC-P4): the floor twins read
	// its managed-floor cells.
	"github.com/marmutapp/superbased-observer/internal/secposture/gatetable": true,
}

func rule(id string) policy.Rule {
	return policy.Rule{
		ID: id, Category: policy.CategoryCodeSecurity, Severity: policy.SeverityHigh,
		AppliesTo: []policy.EventKind{policy.KindShellExec},
		Match:     func(*policy.MatchContext) (bool, string) { return false, "" },
		Observe:   policy.DecisionAsk, Enforce: policy.DecisionDeny, Source: policy.SourcePackSecurity,
		Doc: "test row",
	}
}

func table(rows ...[]policy.Rule) []packRow {
	out := []packRow{{component: "security", lo: 791, hi: 799}, {component: "security.secrets", lo: 721, hi: 739}}
	for i := range out {
		var rs []policy.Rule
		if i < len(rows) {
			rs = rows[i]
		}
		out[i].rules = func() []policy.Rule { return rs }
	}
	return out
}

func all(string) bool { return true }

// TestComposeValidation has one row per validation rule (section 4.7 item
// 1 and acceptance A: a colliding or out-of-range id is rejected).
func TestComposeValidation(t *testing.T) {
	t.Parallel()
	bad := func(mut func(*policy.Rule)) []policy.Rule {
		r := rule("S-791")
		mut(&r)
		return []policy.Rule{r}
	}
	cases := []struct {
		name string
		tbl  []packRow
		want string
	}{
		{"valid", table([]policy.Rule{rule("S-791")}), ""},
		{"out of range", table([]policy.Rule{rule("S-721")}), "outside"},
		{"not an S-7 id", table([]policy.Rule{rule("R-112")}), "not an S-7xx"},
		{"malformed number", table([]policy.Rule{rule("S-7x1")}), "not an S-7xx"},
		{"duplicate across rows", table([]policy.Rule{rule("S-791")}, []policy.Rule{rule("S-791")}), "outside"},
		{"variants of one id in a row", table([]policy.Rule{rule("S-791"), rule("S-791")}), ""},
		{"variant with another severity", table([]policy.Rule{rule("S-791"), bad(func(r *policy.Rule) { r.Severity = policy.SeverityInfo })[0]}), "appears twice"},
		{"wrong source", table(bad(func(r *policy.Rule) { r.Source = "user" })), "has source"},
		{"wrong category", table(bad(func(r *policy.Rule) { r.Category = policy.CategoryBoundary })), "has category"},
		{"no doc", table(bad(func(r *policy.Rule) { r.Doc = " " })), "no Doc"},
		{"no matcher", table(bad(func(r *policy.Rule) { r.Match = nil })), "exactly one"},
	}
	for _, tc := range cases {
		_, err := compose(tc.tbl, all)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: unexpected error %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: error %v, want one containing %q", tc.name, err, tc.want)
		}
	}
}

func TestComposeOnlyActiveChildren(t *testing.T) {
	t.Parallel()
	tbl := table([]policy.Rule{rule("S-791")})
	c, err := compose(tbl, func(id string) bool { return id == "security.secrets" })
	if err != nil || len(c.Rules) != 0 {
		t.Fatalf("an inactive child composes nothing: %+v, %v", c, err)
	}
	c, err = compose(tbl, all)
	if err != nil || len(c.Rules) != 1 || len(c.Components) != 1 || c.PackVersion != PackVersion {
		t.Fatalf("an active child composes its rows: %+v, %v", c, err)
	}
	if c, _ := compose(tbl, nil); len(c.Rules) != 0 {
		t.Fatal("no predicate composes nothing")
	}
}

// TestShippedTableIsValid: the real table composes with every child on.
func TestShippedTableIsValid(t *testing.T) {
	t.Parallel()
	if _, err := Compose(all); err != nil {
		t.Fatal(err)
	}
	for _, r := range packTable {
		if r.lo < 701 || r.hi > 799 || r.lo > r.hi {
			t.Errorf("%s: range S-%d to S-%d", r.component, r.lo, r.hi)
		}
	}
}

// TestComposedRulesRequirePackMembership: a composed row fires only while
// its child is in Event.Security.Packs (audit P-002 finding 1). The hook
// composes every pillar row while the module is active, so a child that
// is off in the posture must stay silent.
func TestComposedRulesRequirePackMembership(t *testing.T) {
	t.Parallel()
	hit := rule("S-721")
	hit.Match = func(*policy.MatchContext) (bool, string) { return true, "hit" }
	cmd := rule("S-791")
	cmd.Match = nil
	cmd.MatchCmd = func(*policy.MatchContext, *policy.Command) (bool, string) { return true, "hit" }
	c, err := compose(table([]policy.Rule{cmd}, []policy.Rule{hit}), all)
	if err != nil || len(c.Rules) != 2 {
		t.Fatalf("compose: %+v, %v", c, err)
	}
	fire := func(r policy.Rule, sec *policy.Security) bool {
		ctx := &policy.MatchContext{Event: &policy.Event{Security: sec}}
		if r.Match != nil {
			ok, _ := r.Match(ctx)
			return ok
		}
		ok, _ := r.MatchCmd(ctx, &policy.Command{})
		return ok
	}
	cases := []struct {
		name     string
		sec      *policy.Security
		cmd, hit bool
	}{
		{"no security facts", nil, false, false},
		{"empty pack set", &policy.Security{}, false, false},
		{"root only", &policy.Security{Packs: []string{"security"}}, true, false},
		{"secrets only", &policy.Security{Packs: []string{"security.secrets"}}, false, true},
		{"both", &policy.Security{Packs: []string{"security", "security.secrets"}}, true, true},
		{"another child", &policy.Security{Packs: []string{"security.trust"}}, false, false},
	}
	for _, tc := range cases {
		if got := fire(c.Rules[0], tc.sec); got != tc.cmd {
			t.Errorf("%s: root row fired %v, want %v", tc.name, got, tc.cmd)
		}
		if got := fire(c.Rules[1], tc.sec); got != tc.hit {
			t.Errorf("%s: secrets row fired %v, want %v", tc.name, got, tc.hit)
		}
	}
	if fire(c.Rules[1], nil) || fire(c.Rules[0], nil) {
		t.Fatal("an event without Security facts must not match")
	}
}
