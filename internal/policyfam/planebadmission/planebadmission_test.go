package planebadmission

import (
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policyfam/admission"
	"github.com/marmutapp/superbased-observer/internal/promptadmit"
)

func TestCompileBodyRows(t *testing.T) {
	det := `{"mode":"enforce","prefilter":{"deny":["drop table"]}}`
	cases := []struct {
		name    string
		raw     string
		wantErr error
		bad     bool
		check   func(t *testing.T, s PolicySpec)
	}{
		{name: "node lane defaults OFF", raw: `{"admission":` + det + `}`, check: func(t *testing.T, s PolicySpec) {
			if s.NodeLane || s.LatencyBudgetMS != DefaultLatencyBudgetMS || !Enforces(s) {
				t.Fatalf("spec = %+v", s)
			}
		}},
		{name: "node lane flip is explicit", raw: `{"admission":` + det + `,"node_lane":true,"latency_budget_ms":300}`, check: func(t *testing.T, s PolicySpec) {
			if !s.NodeLane || s.LatencyBudgetMS != 300 {
				t.Fatalf("spec = %+v", s)
			}
		}},
		{name: "scope defaults to user_prompts", raw: `{"admission":` + det + `}`, check: func(t *testing.T, s PolicySpec) {
			if s.Scope != promptadmit.ScopeUserPrompts {
				t.Fatalf("scope = %q", s.Scope)
			}
		}},
		{name: "scope user_prompts is explicit", raw: `{"admission":` + det + `,"scope":"user_prompts"}`, check: func(t *testing.T, s PolicySpec) {
			if s.Scope != promptadmit.ScopeUserPrompts {
				t.Fatalf("scope = %q", s.Scope)
			}
		}},
		{name: "scope all_calls", raw: `{"admission":` + det + `,"scope":"all_calls"}`, check: func(t *testing.T, s PolicySpec) {
			if s.Scope != promptadmit.ScopeAllCalls {
				t.Fatalf("scope = %q", s.Scope)
			}
		}},
		{name: "scope outside the closed enum", raw: `{"admission":` + det + `,"scope":"everything"}`, bad: true},
		{name: "missing admission", raw: `{"node_lane":true}`, bad: true},
		{name: "negative latency", raw: `{"admission":` + det + `,"latency_budget_ms":-1}`, bad: true},
		{name: "invalid inner", raw: `{"admission":{"mode":"enforce","bogus":1}}`, bad: true},
		{name: "judged criteria need a gateway judge route", raw: `{"admission":{"mode":"enforce","criteria":[{"id":"c1","type":"custom","definition":"secrets"}]}}`, bad: true},
		{name: "judged criteria with a judge route", raw: `{"admission":{"mode":"enforce","criteria":[{"id":"c1","type":"custom","definition":"secrets"}]},"judge_upstream_id":"judge-up"}`, check: func(t *testing.T, s PolicySpec) {
			if !RequiresJudge(s) || s.JudgeUpstreamID != "judge-up" {
				t.Fatalf("spec = %+v", s)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, canon, err := CompileBody([]byte(tc.raw), 1<<20)
			if tc.bad {
				if err == nil {
					t.Fatal("compiled, want error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v", err)
			}
			if !strings.Contains(string(canon), `"admission"`) {
				t.Fatalf("canonical body lost the inner admission body: %s", canon)
			}
			tc.check(t, spec)
		})
	}
	// Canonical bytes are stable across textual variants.
	_, c1, err1 := CompileBody([]byte(`{"admission":`+det+`,"node_lane":false}`), 0)
	_, c2, err2 := CompileBody([]byte(`{ "node_lane": false , "admission": `+det+` }`), 0)
	if err1 != nil || err2 != nil || len(c1) == 0 {
		t.Fatalf("zero-cap compile: %v %v", err1, err2)
	}
	if string(c1) != string(c2) {
		t.Fatalf("canonical bytes differ:\n%s\n%s", c1, c2)
	}
	// The default scope canonicalises to the pre-scope bytes (a body written
	// before the key existed hashes as it did); all_calls is kept.
	_, c3, err3 := CompileBody([]byte(`{"admission":`+det+`,"scope":"user_prompts"}`), 0)
	_, c4, err4 := CompileBody([]byte(`{"admission":`+det+`,"scope":"all_calls"}`), 0)
	if err3 != nil || err4 != nil {
		t.Fatalf("scope compile: %v %v", err3, err4)
	}
	if string(c3) != string(c1) || strings.Contains(string(c1), "scope") {
		t.Fatalf("explicit default scope changed the canonical bytes:\n%s\n%s", c3, c1)
	}
	if !strings.Contains(string(c4), `"scope":"all_calls"`) {
		t.Fatalf("all_calls lost from canonical bytes: %s", c4)
	}
	if admission.ModeEnforce == admission.ModeOff {
		t.Fatal("mode vocabulary collapsed")
	}
}

// TestLatencyBudgetExplicitSurvivesTheSignedCanonicalBytes pins F1 (fix round
// 1): the node compiles the CANONICAL bytes the org server signed, never the
// admin's raw body, so an absent budget must stay absent there and a set one
// must stay set.
func TestLatencyBudgetExplicitSurvivesTheSignedCanonicalBytes(t *testing.T) {
	det := `{"mode":"enforce","prefilter":{"deny":["x"]}}`
	cases := []struct {
		name         string
		raw          string
		wantExplicit bool
		wantMS       int
	}{
		{name: "absent stays absent", raw: `{"admission":` + det + `,"node_lane":true}`, wantExplicit: false, wantMS: DefaultLatencyBudgetMS},
		{name: "explicit default stays explicit", raw: `{"admission":` + det + `,"latency_budget_ms":1500}`, wantExplicit: true, wantMS: 1500},
		{name: "explicit value stays explicit", raw: `{"admission":` + det + `,"latency_budget_ms":8000}`, wantExplicit: true, wantMS: 8000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, signed, err := CompileBody([]byte(tc.raw), 0)
			if err != nil {
				t.Fatal(err)
			}
			node, again, err := CompileBody(signed, 0)
			if err != nil {
				t.Fatal(err)
			}
			if node.LatencyBudgetExplicit != tc.wantExplicit || node.LatencyBudgetMS != tc.wantMS {
				t.Fatalf("node spec explicit=%v ms=%d, want %v %d (signed %s)", node.LatencyBudgetExplicit, node.LatencyBudgetMS, tc.wantExplicit, tc.wantMS, signed)
			}
			if string(again) != string(signed) {
				t.Fatalf("canonical bytes are not a fixed point:\n%s\n%s", signed, again)
			}
		})
	}
}
