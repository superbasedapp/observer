package secassess

import (
	"encoding/json"
	"reflect"
	"testing"
)

// Tests of the lenient reading of the evidence fields (lenient.go): the natural
// spellings an agent guesses are read, a shape that cannot be read is marked and
// never fails the typed decode of the model.

func TestPTRequestJSON(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want PTRequest
		bad  string
	}{
		{"one line with a body", `"PUT /a/b body here"`, PTRequest{Method: "PUT", Path: "/a/b", Body: "body here"}, ""},
		{"one line that is no request", `"send fifty bad logins"`, PTRequest{}, ""},
		{"the structured form", `{"method":"GET","path":"/x"}`, PTRequest{Method: "GET", Path: "/x"}, ""},
		{
			"headers as a list", `{"method":"GET","path":"/x","headers":[{"name":"Accept","value":"a/b"}]}`,
			PTRequest{Method: "GET", Path: "/x", Headers: []PTHeader{{"Accept", "a/b"}}},
			"",
		},
		{
			"headers as a map, in name order", `{"method":"POST","path":"/x","headers":{"X-B":"2","Content-Type":"application/json"}}`,
			PTRequest{Method: "POST", Path: "/x", Headers: []PTHeader{{"Content-Type", "application/json"}, {"X-B", "2"}}},
			"",
		},
		{
			"headers as lines", `{"method":"GET","path":"/x","headers":["Accept: a/b","Origin:http://x"]}`,
			PTRequest{Method: "GET", Path: "/x", Headers: []PTHeader{{"Accept", "a/b"}, {"Origin", "http://x"}}},
			"",
		},
		{
			"headers as one line", `{"method":"GET","path":"/x","headers":"Accept: a/b"}`,
			PTRequest{Method: "GET", Path: "/x", Headers: []PTHeader{{"Accept", "a/b"}}},
			"",
		},
		{
			"headers as one header object", `{"method":"GET","path":"/x","headers":{"name":"Accept","value":"a/b"}}`,
			PTRequest{Method: "GET", Path: "/x", Headers: []PTHeader{{"Accept", "a/b"}}},
			"",
		},
		{
			"one header object keeps its one header when a key is added", `{"method":"GET","path":"/x","headers":{"name":"Accept","value":"a/b","note":"why"}}`,
			PTRequest{Method: "GET", Path: "/x", Headers: []PTHeader{{"Accept", "a/b"}}},
			"",
		},
		{
			"a header map is still a map when it has no value key", `{"method":"GET","path":"/x","headers":{"name":"x","X-A":"1"}}`,
			PTRequest{Method: "GET", Path: "/x", Headers: []PTHeader{{"X-A", "1"}, {"name", "x"}}},
			"",
		},
		{
			"a header map value that is a number or a list", `{"method":"GET","path":"/x","headers":{"X-N":5,"X-L":["a","b"]}}`,
			PTRequest{Method: "GET", Path: "/x", Headers: []PTHeader{{"X-L", "a, b"}, {"X-N", "5"}}},
			"",
		},
		{
			"a header whose value is a number", `{"method":"GET","path":"/x","headers":[{"name":"X-N","value":7}]}`,
			PTRequest{Method: "GET", Path: "/x", Headers: []PTHeader{{"X-N", "7"}}},
			"",
		},
		{"a body that is an object", `{"method":"POST","path":"/x","body":{"user": "a", "n": 1}}`, PTRequest{Method: "POST", Path: "/x", Body: `{"user":"a","n":1}`}, ""},
		{"a body that is a list", `{"method":"POST","path":"/x","body":[1, 2]}`, PTRequest{Method: "POST", Path: "/x", Body: `[1,2]`}, ""},
		{"a body that is a number", `{"method":"POST","path":"/x","body":42}`, PTRequest{Method: "POST", Path: "/x", Body: `42`}, ""},
		{"a body that is null", `{"method":"POST","path":"/x","body":null}`, PTRequest{Method: "POST", Path: "/x"}, ""},
		{"a method that is a number", `{"method":5,"path":"/x"}`, PTRequest{Method: "5", Path: "/x"}, ""},
		{"a path that is an object", `{"method":"GET","path":{"a":1}}`, PTRequest{Method: "GET"}, "path"},
		{"a method that is a list", `{"method":["GET"],"path":"/x"}`, PTRequest{Path: "/x"}, "method"},
		{"headers that are a number", `{"method":"GET","path":"/x","headers":7}`, PTRequest{Method: "GET", Path: "/x"}, "headers"},
		{
			"a header map value that is an object", `{"method":"GET","path":"/x","headers":{"X-O":{"a":1}}}`,
			PTRequest{Method: "GET", Path: "/x", Headers: []PTHeader{{"X-O", ""}}},
			"headers",
		},
		{"a request that is a number", `5`, PTRequest{}, "request"},
		{"a request that is a list", `[1]`, PTRequest{}, "request"},
		{"a request that is true", `true`, PTRequest{}, "request"},
		{"null", `null`, PTRequest{}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got PTRequest
			if err := json.Unmarshal([]byte(c.in), &got); err != nil {
				t.Fatalf("error: %v", err)
			}
			if got.Unread != c.bad {
				t.Errorf("bad = %q, want %q", got.Unread, c.bad)
			}
			got.Unread = ""
			if !equalRequest(got, c.want) {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
		})
	}
	t.Run("a null request in a step is nil", func(t *testing.T) {
		var p struct{ R *PTRequest }
		if err := json.Unmarshal([]byte(`{"R":null}`), &p); err != nil || p.R != nil {
			t.Fatalf("%+v %v", p, err)
		}
	})
	t.Run("one word is no request", func(t *testing.T) {
		if got := parseRequestLine("GET"); got.Method != "" || got.Path != "" || got.Body != "" {
			t.Errorf("%+v", got)
		}
	})
}

func TestPTMatchJSON(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want PTMatch
		bad  string
	}{
		{
			"the structured form", `{"status":200,"body_contains":["a"],"body_not_contains":["b"],"header_present":["X-A"],"header_absent":["X-B"],"header_contains":[{"name":"Set-Cookie","value":"HttpOnly"}]}`,
			PTMatch{Status: 200, BodyContains: []string{"a"}, BodyNotContains: []string{"b"}, HeaderPresent: []string{"X-A"}, HeaderAbsent: []string{"X-B"}, HeaderContains: []PTHeader{{"Set-Cookie", "HttpOnly"}}},
			"",
		},
		{"a status as a numeric string", `{"status":"403"}`, PTMatch{Status: 403}, ""},
		{"a status as a float", `{"status":403.0}`, PTMatch{Status: 403}, ""},
		{"a status as words", `{"status":"forbidden"}`, PTMatch{}, "status"},
		{"a status as a list", `{"status":[403]}`, PTMatch{}, "status"},
		{"a status that is null", `{"status":null,"body_contains":["a"]}`, PTMatch{BodyContains: []string{"a"}}, ""},
		{"body_contains as a string", `{"body_contains":"secret-row"}`, PTMatch{BodyContains: []string{"secret-row"}}, ""},
		{"body_not_contains as a string", `{"body_not_contains":"denied"}`, PTMatch{BodyNotContains: []string{"denied"}}, ""},
		{"header_present as a string", `{"header_present":"X-A"}`, PTMatch{HeaderPresent: []string{"X-A"}}, ""},
		{"a list with a number in it", `{"body_contains":["a", 5]}`, PTMatch{BodyContains: []string{"a", "5"}}, ""},
		{"a list with an object in it", `{"body_contains":["a", {"x":1}]}`, PTMatch{BodyContains: []string{"a"}}, "body_contains"},
		{"body_contains as an object", `{"body_contains":{"a":1}}`, PTMatch{}, "body_contains"},
		{
			"header_contains as a map", `{"header_contains":{"Set-Cookie":"HttpOnly","Cache-Control":"no-store"}}`,
			PTMatch{HeaderContains: []PTHeader{{"Cache-Control", "no-store"}, {"Set-Cookie", "HttpOnly"}}},
			"",
		},
		// The first live run (2026-11-15): "(name and value)" in the prompt, and a
		// single object read as a map of two headers called name and value, so
		// F-12 and F-13 could never hold. One object is one header.
		{
			"header_contains as one object (the live run's F-12)", `{"status":302,"header_contains":{"name":"Location","value":"https://evil.example/phish"}}`,
			PTMatch{Status: 302, HeaderContains: []PTHeader{{"Location", "https://evil.example/phish"}}},
			"",
		},
		{"header_contains as one object, the name and value in any key order", `{"header_contains":{"value":"HttpOnly","name":"Set-Cookie"}}`, PTMatch{HeaderContains: []PTHeader{{"Set-Cookie", "HttpOnly"}}}, ""},
		{"header_contains as one object with a name only", `{"header_contains":{"name":"Set-Cookie"}}`, PTMatch{HeaderContains: []PTHeader{{"Set-Cookie", ""}}}, ""},
		{"header_contains as one object with a number value", `{"header_contains":{"name":"X-N","value":7}}`, PTMatch{HeaderContains: []PTHeader{{"X-N", "7"}}}, ""},
		{"header_contains as one object with a list value", `{"header_contains":{"name":"X-L","value":["a","b"]}}`, PTMatch{HeaderContains: []PTHeader{{"X-L", "a, b"}}}, ""},
		{"header_contains as one object whose value is an object", `{"header_contains":{"name":"X-O","value":{"a":1}}}`, PTMatch{HeaderContains: []PTHeader{{"X-O", ""}}}, "header_contains"},
		{"header_contains as one object whose name is a list", `{"header_contains":{"name":["a"],"value":"x"}}`, PTMatch{HeaderContains: []PTHeader{{"", "x"}}}, "header_contains"},
		{
			"header_contains as a map that holds a header called name beside others", `{"header_contains":{"name":"x","Set-Cookie":"HttpOnly"}}`,
			PTMatch{HeaderContains: []PTHeader{{"Set-Cookie", "HttpOnly"}, {"name", "x"}}},
			"",
		},
		{"header_contains as lines", `{"header_contains":["Set-Cookie: HttpOnly"]}`, PTMatch{HeaderContains: []PTHeader{{"Set-Cookie", "HttpOnly"}}}, ""},
		{"header_contains as one line", `{"header_contains":"Set-Cookie: HttpOnly"}`, PTMatch{HeaderContains: []PTHeader{{"Set-Cookie", "HttpOnly"}}}, ""},
		{"header_contains as a number", `{"header_contains":5}`, PTMatch{}, "header_contains"},
		{"a condition written as a sentence", `"the status is 403 and the body says denied"`, PTMatch{}, "condition"},
		{"a condition that is a list", `["status 403"]`, PTMatch{}, "condition"},
		{"a condition that is a number", `403`, PTMatch{}, "condition"},
		{"null", `null`, PTMatch{}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got PTMatch
			if err := json.Unmarshal([]byte(c.in), &got); err != nil {
				t.Fatalf("error: %v", err)
			}
			if got.Unread != c.bad {
				t.Errorf("bad = %q, want %q", got.Unread, c.bad)
			}
			got.Unread = ""
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestPTIndicatorAndStepJSON(t *testing.T) {
	var ind PTIndicator
	for in, bad := range map[string]string{
		`{"control":"p1","attack":"p2","when":{"status":"200"}}`: "",
		`"p1 differs from p2"`:             "indicator",
		`{"control":["p1"],"attack":"p2"}`: "control",
		`7`:                                "indicator",
	} {
		if err := json.Unmarshal([]byte(in), &ind); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if ind.Unread != bad {
			t.Errorf("%s: bad = %q, want %q", in, ind.Unread, bad)
		}
	}
	if err := json.Unmarshal([]byte(`{"control":"p1","attack":"p2","when":{"status":"200"}}`), &ind); err != nil || ind.When == nil || ind.When.Status != 200 {
		t.Errorf("indicator with a string status: %+v %v", ind, err)
	}
	var repro []PTRepro
	if err := json.Unmarshal([]byte(`["Send it", {"step":"Then this","request":"GET /x"}, {"step":"No request","request":7}, 5]`), &repro); err != nil || len(repro) != 4 {
		t.Fatalf("%+v %v", repro, err)
	}
	if repro[0].Step != "Send it" || repro[1].Step != "Then this" || repro[1].Request == nil || repro[1].Request.Path != "/x" ||
		repro[2].Request == nil || repro[2].Request.Unread != "request" || repro[3].Step != "" {
		t.Errorf("steps = %+v", repro)
	}
}

// TestEvidenceShapesDegradeNotRefuse: each natural mistake in the evidence
// fields keeps the model and the finding; a shape that cannot be read is one
// counted issue and the finding's evidence says what is missing.
func TestEvidenceShapesDegradeNotRefuse(t *testing.T) {
	setRepro := func(req any) func(m map[string]any) {
		return func(m map[string]any) {
			obj(arr(m["findings"])[0])["reproduction"] = []any{map[string]any{"step": "Send it", "request": req}}
		}
	}
	setWhen := func(when any) func(m map[string]any) {
		return func(m map[string]any) { obj(obj(arr(m["findings"])[0])["indicator"])["when"] = when }
	}
	base := &PTRequest{Method: "POST", Path: "/login"} // the fixture's own request, kept when only the indicator changes
	cases := []struct {
		name    string
		mut     func(m map[string]any)
		request *PTRequest // the kept request of the first step; nil when none
		when    *PTMatch   // the kept condition; nil when none
		issue   string     // the issue that must be counted, "" for none
	}{
		{
			"headers as a map", setRepro(map[string]any{"method": "POST", "path": "/login", "headers": map[string]any{"Content-Type": "application/json"}}),
			&PTRequest{Method: "POST", Path: "/login", Headers: []PTHeader{{"Content-Type", "application/json"}}}, &PTMatch{Status: 200, BodyContains: []string{"secret-row"}}, "",
		},
		{
			"a body that is an object", setRepro(map[string]any{"method": "POST", "path": "/login", "body": map[string]any{"user": "a"}}),
			&PTRequest{Method: "POST", Path: "/login", Body: `{"user":"a"}`}, &PTMatch{Status: 200, BodyContains: []string{"secret-row"}}, "",
		},
		{
			"a condition as a sentence", setWhen("the status is 403"),
			base, nil, "evidence_shape_dropped",
		},
		{
			"a status as a string", setWhen(map[string]any{"status": "200", "body_contains": []any{"secret-row"}}),
			base, &PTMatch{Status: 200, BodyContains: []string{"secret-row"}}, "",
		},
		{
			"body_contains as a string", setWhen(map[string]any{"status": 200, "body_contains": "secret-row"}),
			base, &PTMatch{Status: 200, BodyContains: []string{"secret-row"}}, "",
		},
		{
			"header_contains as a map", setWhen(map[string]any{"header_contains": map[string]any{"Set-Cookie": "HttpOnly"}}),
			base, &PTMatch{HeaderContains: []PTHeader{{"Set-Cookie", "HttpOnly"}}}, "",
		},
		{
			"header_contains as one object", setWhen(map[string]any{"header_contains": map[string]any{"name": "Location", "value": "https://evil.example/phish"}}),
			base, &PTMatch{HeaderContains: []PTHeader{{"Location", "https://evil.example/phish"}}}, "",
		},
		{
			"headers as one header object", setRepro(map[string]any{"method": "POST", "path": "/login", "headers": map[string]any{"name": "Content-Type", "value": "application/json"}}),
			&PTRequest{Method: "POST", Path: "/login", Headers: []PTHeader{{"Content-Type", "application/json"}}}, &PTMatch{Status: 200, BodyContains: []string{"secret-row"}}, "",
		},
		{
			"a status that is words keeps the rest", setWhen(map[string]any{"status": "forbidden", "body_contains": []any{"secret-row"}}),
			base, &PTMatch{BodyContains: []string{"secret-row"}}, "evidence_shape_dropped",
		},
		{"a request that is a number", setRepro(7), nil, &PTMatch{Status: 200, BodyContains: []string{"secret-row"}}, "evidence_shape_dropped"},
		{
			"headers that are a number", setRepro(map[string]any{"method": "GET", "path": "/x", "headers": 7}),
			&PTRequest{Method: "GET", Path: "/x"}, &PTMatch{Status: 200, BodyContains: []string{"secret-row"}}, "evidence_shape_dropped",
		},
		{
			"an indicator that is a sentence", func(m map[string]any) { obj(arr(m["findings"])[0])["indicator"] = "p2 differs from p1" },
			base, nil, "evidence_shape_dropped",
		},
		{
			"a step that is a sentence", func(m map[string]any) { obj(arr(m["findings"])[0])["reproduction"] = []any{"Send fifty bad logins"} },
			nil, &PTMatch{Status: 200, BodyContains: []string{"secret-row"}}, "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := evValidate(t, evDoc(t, c.mut), ProbeFacts{})
			if r.Report.Fatal != "" || r.Report.State == "invalid" {
				t.Fatalf("the model was refused: fatal %q state %q (%s)", r.Report.Fatal, r.Report.State, issueCodes(r.Report))
			}
			f := finding0(t, r)
			if len(f.Reproduction) != 1 {
				t.Fatalf("steps = %+v", f.Reproduction)
			}
			if got := f.Reproduction[0].Request; (got == nil) != (c.request == nil) || (got != nil && !equalRequest(*got, *c.request)) {
				t.Errorf("request = %+v, want %+v", got, c.request)
			}
			var when *PTMatch
			if f.Indicator != nil {
				when = f.Indicator.When
			}
			if !reflect.DeepEqual(when, c.when) {
				t.Errorf("condition = %+v, want %+v", when, c.when)
			}
			if c.issue != "" && !hasIssue(r.Report, "V5", c.issue) {
				t.Errorf("missing V5:%s; got %s", c.issue, issueCodes(r.Report))
			}
			if c.issue == "" && hasIssue(r.Report, "V5", "evidence_shape_dropped") {
				t.Errorf("a natural shape was reported as unreadable: %s", issueCodes(r.Report))
			}
		})
	}
}
