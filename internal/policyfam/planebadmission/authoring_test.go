package planebadmission

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func mustCompile(t *testing.T, raw string) PolicySpec {
	t.Helper()
	s, _, err := CompileBody([]byte(raw), 0)
	if err != nil {
		t.Fatalf("compile %s: %v", raw, err)
	}
	return s
}

const judgedInner = `{"mode":"observe","criteria":[{"id":"AD-100","type":"custom","decision":"deny","definition":"x"}]}`

func TestLintWarningsRows(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string // substrings, one per expected line, in order
	}{
		{"user_prompts gateway only", `{"admission":` + judgedInner + `,"judge_upstream_id":"u1"}`, []string{"node_lane is off"}},
		{"all_calls judged", `{"admission":` + judgedInner + `,"judge_upstream_id":"u1","scope":"all_calls","node_lane":true}`, []string{"15x the judge calls"}},
		{"all_calls deterministic", `{"admission":{"mode":"observe","prefilter":{"deny":["x"]}},"scope":"all_calls","node_lane":true}`, []string{"costs no judge calls"}},
		{"strict enforce judged node", `{"admission":{"mode":"enforce","strict":true,"criteria":[{"id":"AD-100","type":"custom","decision":"deny","definition":"x"}]},"judge_upstream_id":"u1","node_lane":true}`, []string{"strict + enforce", "run it in observe first"}},
		{"mode off says nothing", `{"admission":{"mode":"off"}}`, nil},
		{"node lane only", `{"admission":` + judgedInner + `,"node_lane":true}`, []string{"node lane only"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := LintWarnings(mustCompile(t, tc.raw))
			if len(got) != len(tc.want) {
				t.Fatalf("got %d warnings %q, want %d", len(got), got, len(tc.want))
			}
			for i, w := range tc.want {
				if !strings.Contains(got[i], w) {
					t.Fatalf("warning %d = %q, want it to contain %q", i, got[i], w)
				}
			}
		})
	}
}

func TestJudgeBudgets(t *testing.T) {
	absent := mustCompile(t, `{"admission":{"mode":"observe"}}`)
	if NodeLaneJudgeBudget(absent) != 10*time.Second || GatewayJudgeBudget(absent) != 1500*time.Millisecond {
		t.Fatalf("absent budget: node %v gateway %v", NodeLaneJudgeBudget(absent), GatewayJudgeBudget(absent))
	}
	set := mustCompile(t, `{"admission":{"mode":"observe"},"latency_budget_ms":700}`)
	if NodeLaneJudgeBudget(set) != 700*time.Millisecond || GatewayJudgeBudget(set) != 700*time.Millisecond {
		t.Fatalf("explicit budget: node %v gateway %v", NodeLaneJudgeBudget(set), GatewayJudgeBudget(set))
	}
}

// TestAuthoringVocabCompiles pins that every vocabulary value the form can
// pick is one the compiler accepts.
func TestAuthoringVocabCompiles(t *testing.T) {
	v := AuthoringVocab()
	for _, m := range v.Modes {
		for _, sc := range v.Scopes {
			mustCompile(t, `{"admission":{"mode":"`+m+`"},"scope":"`+sc+`"}`)
		}
	}
	for _, ty := range v.CriterionTypes {
		for _, d := range v.Decisions {
			for _, sev := range v.Severities {
				mustCompile(t, `{"admission":{"mode":"observe","criteria":[{"id":"AD-100","type":"`+ty+`","decision":"`+d+`","severity":"`+sev+`","definition":"x","topics":["y"]}]},"judge_upstream_id":"u1"}`)
			}
		}
	}
}

// TestJudgeUpstreamRuleRows pins adm-p2 fix round 1, M2: the gateway judge
// upstream is required only when the AI gateway judges the policy. A judged
// node_lane body with no upstream is node lane only (the relay judges it);
// gateway-only and both-lanes bodies keep the rule.
func TestJudgeUpstreamRuleRows(t *testing.T) {
	const crit = `"criteria":[{"id":"AD-100","type":"custom","decision":"deny","definition":"x"}]`
	cases := []struct {
		name     string
		raw      string
		wantErr  bool
		nodeOnly bool
		// gwJudged is whether the gateway's spec (GatewaySpec) still has
		// judged criteria.
		gateway bool
	}{
		{name: "judged, gateway only, no upstream: refused", raw: `{"admission":{"mode":"enforce",` + crit + `}}`, wantErr: true},
		{name: "judged, node lane only, no upstream", raw: `{"admission":{"mode":"enforce",` + crit + `},"node_lane":true}`, nodeOnly: true},
		{name: "judged, gateway only, upstream", raw: `{"admission":{"mode":"enforce",` + crit + `},"judge_upstream_id":"u"}`, gateway: true},
		{name: "judged, both lanes, upstream", raw: `{"admission":{"mode":"enforce",` + crit + `},"judge_upstream_id":"u","node_lane":true}`, gateway: true},
		{name: "deterministic, node lane, no upstream: nothing judged anywhere", raw: `{"admission":{"mode":"enforce","prefilter":{"deny":["x"]}},"node_lane":true}`},
		{name: "judged, mode off, gateway upstream", raw: `{"admission":{"mode":"off",` + crit + `},"judge_upstream_id":"u"}`, gateway: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _, err := CompileBody([]byte(tc.raw), 0)
			if tc.wantErr {
				if !errors.Is(err, ErrJudgeUpstreamRequired) {
					t.Fatalf("err = %v, want ErrJudgeUpstreamRequired", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if NodeLaneOnly(s) != tc.nodeOnly || RequiresJudge(GatewaySpec(s)) != tc.gateway {
				t.Fatalf("node only %v gateway judged %v, want %v %v", NodeLaneOnly(s), RequiresJudge(GatewaySpec(s)), tc.nodeOnly, tc.gateway)
			}
		})
	}
}

// TestPublishedBodiesCompileUnchanged pins that a body that could be
// published before M2 compiles to the same canonical bytes and the same
// lanes: the rule only admits bodies that were refused before.
func TestPublishedBodiesCompileUnchanged(t *testing.T) {
	raw := `{"admission":{"mode":"enforce","criteria":[{"id":"AD-100","type":"custom","decision":"deny","definition":"x"}]},"judge_upstream_id":"u","node_lane":true}`
	s, canon, err := CompileBody([]byte(raw), 0)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"admission":{"mode":"enforce","prefilter":{},"criteria":[{"id":"AD-100","type":"custom","definition":"x","decision":"deny"}]},"node_lane":true,"judge_upstream_id":"u"}`
	if string(canon) != want {
		t.Fatalf("canonical bytes changed:\n got %s\nwant %s", canon, want)
	}
	if NodeLaneOnly(s) || len(GatewaySpec(s).Admission.Criteria) != len(s.Admission.Criteria) {
		t.Fatalf("an existing both-lanes body changed lanes")
	}
}

// TestGatewaySpecKeepsTheDeterministicLayers pins lows N1: a node-lane-only
// body loses only its judged criteria at the gateway; the prefilter deny
// list and the deterministic criteria stay, and the node's spec is untouched.
func TestGatewaySpecKeepsTheDeterministicLayers(t *testing.T) {
	raw := `{"admission":{"mode":"enforce","prefilter":{"deny":["drop table"]},"criteria":[` +
		`{"id":"AD-100","type":"custom","decision":"deny","definition":"x"},` +
		`{"id":"AD-200","type":"denied_topics","decision":"deny","topics":["payroll"]}]},"node_lane":true}`
	s, _, err := CompileBody([]byte(raw), 0)
	if err != nil {
		t.Fatal(err)
	}
	gw := GatewaySpec(s)
	if RequiresJudge(gw) || len(gw.Admission.Criteria) != 1 || gw.Admission.Criteria[0].ID != "AD-200" {
		t.Fatalf("gateway criteria = %+v", gw.Admission.Criteria)
	}
	if len(gw.Admission.Prefilter.Deny) != 1 || gw.Admission.Mode != s.Admission.Mode || gw.Admission.Strict != s.Admission.Strict {
		t.Fatalf("gateway spec lost a deterministic layer: %+v", gw.Admission)
	}
	if len(s.Admission.Criteria) != 2 {
		t.Fatal("GatewaySpec changed the node's spec")
	}
}
