package trainhalt

import (
	"strings"
	"testing"
)

func vec(vals ...string) []byte {
	var parts []string
	for _, v := range vals {
		parts = append(parts, `{"metric":{},"value":[1731580000.1,"`+v+`"]}`)
	}
	return []byte(`{"status":"success","data":{"resultType":"vector","result":[` + strings.Join(parts, ",") + `]}}`)
}

func TestPromValue(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		want    *float64
		wantErr bool
	}{
		{"one sample", string(vec("12.5")), f(12.5), false},
		{"samples are summed", string(vec("1", "2")), f(3), false},
		{"empty vector is missing", string(vec()), nil, false},
		{"scalar", `{"status":"success","data":{"resultType":"scalar","result":[1731580000,"7"]}}`, f(7), false},
		{"failed query", `{"status":"error","error":"bad_data"}`, nil, true},
		{"matrix refused", `{"status":"success","data":{"resultType":"matrix","result":[]}}`, nil, true},
		{"NaN refused", string(vec("NaN")), nil, true},
		{"not json", `<html>`, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := PromValue([]byte(c.body))
			if (err != nil) != c.wantErr {
				t.Fatalf("err %v", err)
			}
			if (got == nil) != (c.want == nil) || (got != nil && *got != *c.want) {
				t.Fatalf("got %v want %v", got, c.want)
			}
		})
	}
}

func TestFromPrometheus(t *testing.T) {
	res := map[string][]byte{}
	for _, s := range Signals {
		res[s] = vec("0")
	}
	res["pushes_total"], res["pushes_ok"] = vec("150"), vec("150")
	res["api_requests"] = vec("900")
	w, err := FromPrometheus(PhaseCanary, 2700, res)
	if err != nil {
		t.Fatal(err)
	}
	if j := Judge(w, false); j.Verdict != VerdictPromote {
		t.Fatalf("verdict %s\n%s", j.Verdict, j.Text())
	}
	delete(res, "api_5xx_baseline_rate")
	w, _ = FromPrometheus(PhaseCanary, 2700, res)
	if j := Judge(w, false); j.Verdict != VerdictInconclusive {
		t.Fatalf("missing baseline: %s", j.Verdict)
	}
	res["pushes_totl"] = vec("1")
	if _, err := FromPrometheus(PhaseCanary, 2700, res); err == nil {
		t.Fatal("an unknown signal must be refused")
	}
}

func TestParseWindowIsStrict(t *testing.T) {
	if _, err := ParseWindow([]byte(`{"phase":"canary","pushes":1}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := ParseWindow([]byte(`{"phase":"canary"} {}`)); err == nil {
		t.Fatal("trailing data accepted")
	}
	w, err := ParseWindow([]byte(`{"phase":"canary","elapsed_seconds":2700,"pushes_total":3}`))
	if err != nil || w.PushesTotal == nil || *w.PushesTotal != 3 || w.PushesOK != nil {
		t.Fatalf("%+v %v", w, err)
	}
}
