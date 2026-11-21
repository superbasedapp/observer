package secassess

import (
	"strings"
	"testing"
)

// Tests of the forms a logged body is looked at in (matchviews.go) and of the
// header condition rows (headers.go, HiddenConditionText), added after the first
// live run (2026-11-15): one case per table row, the bounds, and the end to end
// cases of the six findings that read No log although their log was genuine.

func TestJSONUnescape(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"no backslash is the same text", `{"a": "b"}`, `{"a": "b"}`},
		{"the live finding F-9", `{"url": "x", "content": "{\"console\": \"internal\", \"status\": \"ok\"}"}`, `{"url": "x", "content": "{"console": "internal", "status": "ok"}"}`},
		{"a quote, a backslash and a slash", `\" \\ \/`, `" \ /`},
		{"the control escapes", `a\nb\tc\rd\be\ff`, "a\nb\tc\rd\be\ff"},
		{"a unicode escape", `café A`, "café A"},
		{"a unicode escape in upper case hex", `é`, "é"},
		{"a surrogate pair is one character", `😀`, "\U0001F600"},
		{"a lone high surrogate stays as written", `x\ud83dy`, `x\ud83dy`},
		{"a lone low surrogate stays as written", `x\ude00y`, `x\ude00y`},
		{"a high surrogate then a plain escape stays as written", `\ud83dA`, `\ud83dA`},
		{"two low surrogates stay as written", `\ude00\ude00`, `\ude00\ude00`},
		{"a unicode escape with too few digits stays", `\u12`, `\u12`},
		{"a unicode escape with a non-hex digit stays", `\u12g4`, `\u12g4`},
		{"an unknown escape keeps its backslash", `\x41 \d \a`, `\x41 \d \a`},
		{"a trailing backslash stays", `abc\`, `abc\`},
		{"decoded once only", `\\\"`, `\"`},
		{"an escaped backslash before n is not a newline", `\\n`, `\n`},
		{"bytes outside ASCII pass through", "café \\\"x\\\" 世界", "café \"x\" 世界"},
		{"an invalid byte passes through", "a\xffb\\n", "a\xffb\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := jsonUnescape(c.in)
			if got != c.want {
				t.Errorf("jsonUnescape(%q) = %q, want %q", c.in, got, c.want)
			}
			if len(got) > len(c.in) {
				t.Errorf("the form is longer than the text: %d against %d bytes", len(got), len(c.in))
			}
		})
	}
	t.Run("never longer than the text, on a long hostile one", func(t *testing.T) {
		in := strings.Repeat(`é😀\"\\\x\u12`, 20000)
		if got := jsonUnescape(in); len(got) > len(in) {
			t.Fatalf("%d bytes from %d", len(got), len(in))
		}
	})
}

// TestBodyViewRows: every row of the table has a case that only that row can
// satisfy, and the forms of a body are distinct and in the table's order.
func TestBodyViewRows(t *testing.T) {
	escaped := `{"content": "{\"console\": \"internal\"}"}`
	cases := []struct {
		row  string // the one row whose form holds the text
		body string
		text string
	}{
		{"B1", escaped, `\"console\": \"internal\"`},
		{"B2", escaped, `"console": "internal"`},
		{"B1", `{"plain": "x"}`, `"plain": "x"`}, // no escape: B2's form is the same text, the row that comes first is the one
	}
	seen := map[string]bool{}
	for _, c := range cases {
		t.Run(c.row+" "+c.text, func(t *testing.T) {
			seen[c.row] = true
			var holders []string
			for _, row := range bodyViewRows {
				if strings.Contains(row.Form(c.body), c.text) {
					holders = append(holders, row.ID)
				}
			}
			if len(holders) == 0 || holders[0] != c.row {
				t.Errorf("rows holding %q: %v, want %s first", c.text, holders, c.row)
			}
			if c.row == "B2" && len(holders) != 1 {
				t.Errorf("the case for B2 must be one only B2 can satisfy: %v", holders)
			}
			if !anyContains(bodyForms(c.body, nil), c.text) {
				t.Errorf("the forms of the body do not hold %q", c.text)
			}
		})
	}
	for _, row := range bodyViewRows {
		if !seen[row.ID] {
			t.Errorf("row %s has no case", row.ID)
		}
	}
	if got := bodyViewRows[0].Form(escaped); got != escaped {
		t.Errorf("B1 must be the stored text as it is, got %q", got)
	}
	if forms := bodyForms(escaped, nil); len(forms) != 2 || forms[0] != escaped || forms[1] == escaped {
		t.Errorf("forms of an escaped body = %q", forms)
	}
	if forms := bodyForms(`{"plain": "x"}`, nil); len(forms) != 1 {
		t.Errorf("a body with no escape has %d forms, want 1", len(forms))
	}
	// The normaliser is applied to each form, so a secret that only shows once the
	// escapes are decoded is hidden the way the condition's own text hides it.
	hide := func(s string) string { return strings.ReplaceAll(s, "hunter2", "[REDACTED]") }
	forms := bodyForms(`{"c": "{\"pw\": \"hunter2\"}"}`, hide)
	if len(forms) != 2 || strings.Contains(forms[1], "hunter2") || !strings.Contains(forms[1], `"pw": "[REDACTED]"`) {
		t.Errorf("forms with a normaliser = %q", forms)
	}
}

// TestPTMatchHoldsBodyForms: a text the condition must contain holds in either
// form of the body; a text it must not contain holds only when neither form has
// it.
func TestPTMatchHoldsBodyForms(t *testing.T) {
	body := `{"url": "http://127.0.0.1:3001/internal/status", "content": "{\"console\": \"internal\", \"status\": \"ok\"}"}`
	cases := []struct {
		name string
		m    PTMatch
		want bool
	}{
		{"the unescaped text (F-9)", PTMatch{BodyContains: []string{`"console": "internal"`}}, true},
		{"the escaped text, as stored", PTMatch{BodyContains: []string{`\"console\": \"internal\"`}}, true},
		{"one text of each form", PTMatch{BodyContains: []string{`"console": "internal"`, `"url": "http://127.0.0.1:3001`}}, true},
		{"a text in neither form", PTMatch{BodyContains: []string{`"console": "public"`}}, false},
		{"one found and one not", PTMatch{BodyContains: []string{`"console": "internal"`, "absent"}}, false},
		{"must not contain, found only in the unescaped form", PTMatch{BodyNotContains: []string{`"console": "internal"`}}, false},
		{"must not contain, found only in the stored form", PTMatch{BodyNotContains: []string{`\"console\"`}}, false},
		{"must not contain, in neither", PTMatch{BodyNotContains: []string{`"console": "public"`}}, true},
		{"status still has to hold", PTMatch{Status: 404, BodyContains: []string{`"console": "internal"`}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := c.m
			if m.Status == 0 {
				m.Status = 200
			}
			if got := m.Holds(200, body, nil); got != c.want {
				t.Fatalf("Holds = %v, want %v", got, c.want)
			}
		})
	}
}

// TestEvidenceBodyForms is row E17 and E18 over the forms: the attack's JSON
// string that carries another body is matched in its decoded form, and the
// control is held to the same forms, so the differential rule is not weakened.
func TestEvidenceBodyForms(t *testing.T) {
	inner := `{"url": "http://127.0.0.1:3001/internal/status", "content": "{\"console\": \"internal\", \"status\": \"ok\"}"}`
	cases := []struct {
		name    string
		control string
		when    map[string]any
		state   EvidenceState
		reason  string
	}{
		{"the live finding F-9 is logged", `{"error": "unsupported address"}`, map[string]any{"status": 200, "body_contains": []any{`"console": "internal"`}}, EvidenceLogged, ""},
		{"the stored form still matches", `{"error": "unsupported address"}`, map[string]any{"status": 200, "body_contains": []any{`\"console\": \"internal\"`}}, EvidenceLogged, ""},
		{"a control that carries the same inner text is not differential", `{"content": "{\"console\": \"internal\"}"}`, map[string]any{"status": 200, "body_contains": []any{`"console": "internal"`}}, EvidenceUnlogged, ReasonNotDifferential},
		{"a must-not-contain is held to the decoded form too", `{"error": "x"}`, map[string]any{"status": 200, "body_not_contains": []any{`"console": "internal"`}}, EvidenceUnlogged, ReasonConditionNotMet},
		{"a text in no form is not met", `{"error": "x"}`, map[string]any{"status": 200, "body_contains": []any{`"console": "public"`}}, EvidenceUnlogged, ReasonConditionNotMet},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pf := evFacts(t, evLog(t, evRec(1, c.control, nil), evRec(2, inner, nil)))
			doc := evDoc(t, func(m map[string]any) { obj(obj(arr(m["findings"])[0])["indicator"])["when"] = c.when })
			f := finding0(t, evValidate(t, doc, pf))
			if f.EvidenceState != c.state || f.EvidenceReason != c.reason {
				t.Fatalf("evidence %q/%q, want %q/%q", f.EvidenceState, f.EvidenceReason, c.state, c.reason)
			}
		})
	}
}

// TestHiddenConditionText: one case per row of the header condition table, and
// the narrowness the rows state (an attribute and a bare word are left alone).
func TestHiddenConditionText(t *testing.T) {
	cases := []struct {
		row  string
		name string
		text string
		want string
	}{
		{"H1", "Content-Type", "json", "json"},
		{"H1", "Location", "https://evil.example/phish", "https://evil.example/phish"},
		{"H1", "Access-Control-Allow-Origin", "https://evil.example", "https://evil.example"},
		{"H1", "www-authenticate", "Bearer realm=x", "Bearer realm=x"}, // named like a credential, carries none
		{"H2", "Set-Cookie", "sid=sess-1001; Path=/", "sid=[REDACTED]; Path=/"},
		{"H2", "set-cookie", "sid=sess-1001", "sid=[REDACTED]"},
		{"H2", "Set-Cookie", "connect.sid=s%3Aabc.def; Path=/; HttpOnly; SameSite=Lax", "connect.sid=[REDACTED]; Path=/; HttpOnly; SameSite=Lax"},
		{"H2", "Set-Cookie", "id=1002; HttpOnly", "id=[REDACTED]; HttpOnly"}, // a fragment that starts inside the name
		{"H2", "Set-Cookie", "sid=[REDACTED]; Path=/", "sid=[REDACTED]; Path=/"},
		{"H3", "Set-Cookie", "HttpOnly", "HttpOnly"},
		{"H3", "Set-Cookie", "SameSite=None; Secure", "SameSite=None; Secure"},
		{"H3", "Set-Cookie", "Path=/", "Path=/"},
		{"H3", "Set-Cookie", "MAX-AGE=3600", "MAX-AGE=3600"},
		{"H3", "Set-Cookie", "sess-1002", "sess-1002"},                   // a bare word is never read as hidden
		{"H3", "Set-Cookie", "sid=", "sid="},                             // nothing to hide
		{"H3", "Set-Cookie", "the cookie sid=abc", "the cookie sid=abc"}, // prose is not a cookie pair
		{"H3", "Set-Cookie", "=abc", "=abc"},
		{"H3", "X-Auth-Token", "abc123", "abc123"}, // another credential header: left as written
		{"H3", "Authorization", "Bearer abc", "Bearer abc"},
	}
	seen := map[string]bool{}
	for _, c := range cases {
		t.Run(c.row+" "+c.name+" "+c.text, func(t *testing.T) {
			seen[c.row] = true
			if got := HiddenConditionText(c.name, c.text); got != c.want {
				t.Errorf("HiddenConditionText(%q, %q) = %q, want %q", c.name, c.text, got, c.want)
			}
			// The row that decides is the one the case names: the first whose Hit holds.
			var by string
			for _, r := range headerConditionRows {
				if r.Hit(c.name, c.text) {
					by = r.ID
					break
				}
			}
			if by != c.row {
				t.Errorf("decided by row %s, the case is for %s", by, c.row)
			}
		})
	}
	for _, r := range headerConditionRows {
		if !seen[r.ID] {
			t.Errorf("row %s has no case", r.ID)
		}
	}
}

// TestEvidenceHeaderConditions: the header findings of the live run end to end.
// F-12 and F-13 name a header and a text that the log holds as written (the bug
// was the reading of the one {"name", "value"} object); F-15 names a cookie with
// its value, which the log hides; F-7 names a bare value.
func TestEvidenceHeaderConditions(t *testing.T) {
	setCookie := func(v string) func(*ProbeRecord) {
		return func(r *ProbeRecord) { r.RespHeaders = append(r.RespHeaders, ProbeHeader{N: "Set-Cookie", V: v}) }
	}
	location := func(v string) func(*ProbeRecord) {
		return func(r *ProbeRecord) {
			r.Status, r.RespHeaders = 302, append(r.RespHeaders, ProbeHeader{N: "Location", V: v})
		}
	}
	cases := []struct {
		name    string
		control func(*ProbeRecord)
		attack  func(*ProbeRecord)
		when    map[string]any
		state   EvidenceState
		reason  string
		issue   bool // the warning that a cookie value was hidden
		stored  []PTHeader
	}{
		{
			"F-12: one header object, a Location that is a URL", location("/notes"), location("https://evil.example/phish"),
			map[string]any{"status": 302, "header_contains": map[string]any{"name": "Location", "value": "https://evil.example/phish"}},
			EvidenceLogged, "", false,
			[]PTHeader{{"Location", "https://evil.example/phish"}},
		},
		{
			"F-13: one header object, a CORS origin", nil, func(r *ProbeRecord) {
				r.RespHeaders = append(r.RespHeaders, ProbeHeader{N: "Access-Control-Allow-Origin", V: "https://evil.example"})
			},
			map[string]any{"status": 200, "header_contains": map[string]any{"name": "Access-Control-Allow-Origin", "value": "https://evil.example"}},
			EvidenceLogged, "", false,
			[]PTHeader{{"Access-Control-Allow-Origin", "https://evil.example"}},
		},
		{
			"the same, as a list of one object", nil, func(r *ProbeRecord) {
				r.RespHeaders = append(r.RespHeaders, ProbeHeader{N: "Access-Control-Allow-Origin", V: "https://evil.example"})
			},
			map[string]any{"status": 200, "header_contains": []any{map[string]any{"name": "Access-Control-Allow-Origin", "value": "https://evil.example"}}},
			EvidenceLogged, "", false,
			[]PTHeader{{"Access-Control-Allow-Origin", "https://evil.example"}},
		},
		{
			"F-15: a cookie copied with its value, the log hides the value", nil, setCookie("sid=[REDACTED]; Path=/"),
			map[string]any{"status": 200, "header_contains": map[string]any{"name": "Set-Cookie", "value": "sid=sess-1001; Path=/"}},
			EvidenceLogged, "", true,
			[]PTHeader{{"Set-Cookie", "sid=[REDACTED]; Path=/"}},
		},
		{
			"a cookie's flags are checked as they are", nil, setCookie("sid=[REDACTED]; Path=/"),
			map[string]any{"status": 200, "header_contains": map[string]any{"name": "Set-Cookie", "value": "Path=/"}},
			EvidenceLogged, "", false,
			[]PTHeader{{"Set-Cookie", "Path=/"}},
		},
		{
			"a flag the cookie lacks is not met", nil, setCookie("sid=[REDACTED]; Path=/"),
			map[string]any{"status": 200, "header_contains": map[string]any{"name": "Set-Cookie", "value": "HttpOnly"}},
			EvidenceUnlogged, ReasonConditionNotMet, false,
			[]PTHeader{{"Set-Cookie", "HttpOnly"}},
		},
		{
			"a different cookie name is not met", nil, setCookie("sid=[REDACTED]; Path=/"),
			map[string]any{"status": 200, "header_contains": map[string]any{"name": "Set-Cookie", "value": "token=abc; Path=/"}},
			EvidenceUnlogged, ReasonConditionNotMet, true,
			[]PTHeader{{"Set-Cookie", "token=[REDACTED]; Path=/"}},
		},
		{
			"F-7: a bare value the log hides stays unmet, and is not read as hidden", setCookie("sid=[REDACTED]; Path=/"), setCookie("sid=[REDACTED]; Path=/"),
			map[string]any{"status": 200, "header_contains": map[string]any{"name": "Set-Cookie", "value": "sess-1002"}},
			EvidenceUnlogged, ReasonConditionNotMet, false,
			[]PTHeader{{"Set-Cookie", "sess-1002"}},
		},
		{
			"a cookie both responses set is not differential", setCookie("sid=[REDACTED]; Path=/"), setCookie("sid=[REDACTED]; Path=/"),
			map[string]any{"status": 200, "header_contains": map[string]any{"name": "Set-Cookie", "value": "sid=sess-1002; Path=/"}},
			EvidenceUnlogged, ReasonNotDifferential, true,
			[]PTHeader{{"Set-Cookie", "sid=[REDACTED]; Path=/"}},
		},
		{
			// A line written by hand that kept the value: the log is compared as the card
			// shows it (hidden), so the condition and the log are in the same form.
			"a hand-written line with the value in it is compared as the card shows it", nil, setCookie("sid=sess-1001; Path=/"),
			map[string]any{"status": 200, "header_contains": map[string]any{"name": "Set-Cookie", "value": "sid=sess-1001; Path=/"}},
			EvidenceLogged, "", true,
			[]PTHeader{{"Set-Cookie", "sid=[REDACTED]; Path=/"}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pf := evFacts(t, evLog(t, evRec(1, `{"ok":true}`, c.control), evRec(2, `{"ok":true}`, c.attack)))
			doc := evDoc(t, func(m map[string]any) { obj(obj(arr(m["findings"])[0])["indicator"])["when"] = c.when })
			r := evValidate(t, doc, pf)
			f := finding0(t, r)
			if f.EvidenceState != c.state || f.EvidenceReason != c.reason {
				t.Fatalf("evidence %q/%q, want %q/%q (issues %s)", f.EvidenceState, f.EvidenceReason, c.state, c.reason, issueCodes(r.Report))
			}
			if got := hasIssue(r.Report, "V5", "indicator_value_hidden"); got != c.issue {
				t.Errorf("the hidden-value warning = %v, want %v (issues %s)", got, c.issue, issueCodes(r.Report))
			}
			if hasIssue(r.Report, "V5", "evidence_shape_dropped") || hasIssue(r.Report, "V5", "indicator_header_dropped") {
				t.Errorf("a natural shape was reported as unreadable or dropped: %s", issueCodes(r.Report))
			}
			if f.Indicator == nil || f.Indicator.When == nil || len(f.Indicator.When.HeaderContains) != len(c.stored) {
				t.Fatalf("condition = %+v", f.Indicator)
			}
			for i, h := range c.stored {
				if got := f.Indicator.When.HeaderContains[i]; got != h {
					t.Errorf("stored header condition %d = %+v, want %+v", i, got, h)
				}
			}
		})
	}
}
