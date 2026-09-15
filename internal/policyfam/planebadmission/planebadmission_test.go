package planebadmission

import (
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policyfam/admission"
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
	if admission.ModeEnforce == admission.ModeOff {
		t.Fatal("mode vocabulary collapsed")
	}
}
