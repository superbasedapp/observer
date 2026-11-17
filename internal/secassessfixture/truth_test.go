package secassessfixture

import (
	"strings"
	"testing"
)

func TestLineOf(t *testing.T) {
	src := []byte("alpha\nbeta gamma\r\ndelta\nbeta tail\n")
	tests := []struct {
		name    string
		anchor  string
		want    int
		wantErr string
	}{
		{name: "first line", anchor: "alpha", want: 1},
		{name: "crlf line", anchor: "gamma", want: 2},
		{name: "later line", anchor: "delta", want: 3},
		{name: "twice is an error", anchor: "beta", wantErr: "occurs 2 times"},
		{name: "absent is an error", anchor: "zeta", wantErr: "not found"},
		{name: "empty is an error", anchor: "", wantErr: "empty anchor"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := LineOf(src, tc.anchor)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("LineOf(%q) error = %v, want one containing %q", tc.anchor, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("LineOf(%q): %v", tc.anchor, err)
			}
			if got != tc.want {
				t.Fatalf("LineOf(%q) = %d, want %d", tc.anchor, got, tc.want)
			}
		})
	}
}

func TestLineTextAndComment(t *testing.T) {
	src := []byte("x = 1\r\n    # note\nlast")
	if got := LineText(src, 1); got != "x = 1" {
		t.Fatalf("LineText(1) = %q", got)
	}
	if got := LineText(src, 4); got != "" {
		t.Fatalf("LineText past the end = %q", got)
	}
	for line, want := range map[string]bool{"    # note": true, "#!/usr/bin/env python3": true, "x = 1  # tail": false, "": false} {
		if got := IsCommentLine(line); got != want {
			t.Errorf("IsCommentLine(%q) = %v, want %v", line, got, want)
		}
	}
}

func resp(status int, body string, headers map[string][]string) Response {
	return Response{Status: status, Body: body, Header: headers}
}

func TestIndicatorHolds(t *testing.T) {
	cookie := func(v string) map[string][]string { return map[string][]string{"Set-Cookie": {v}} }
	tests := []struct {
		name string
		in   Indicator
		resp []Response
		want bool
	}{
		{name: "no response", in: Indicator{Status: 200}, resp: nil, want: false},
		{name: "empty indicator holds", in: Indicator{}, resp: []Response{resp(500, "", nil)}, want: true},
		{name: "status match", in: Indicator{Status: 200}, resp: []Response{resp(200, "", nil)}, want: true},
		{name: "status mismatch", in: Indicator{Status: 200}, resp: []Response{resp(403, "", nil)}, want: false},
		{name: "body contains all", in: Indicator{BodyContains: []string{"a", "b"}}, resp: []Response{resp(200, "xaxb", nil)}, want: true},
		{name: "body lacks one", in: Indicator{BodyContains: []string{"a", "z"}}, resp: []Response{resp(200, "xaxb", nil)}, want: false},
		{name: "body must not contain", in: Indicator{BodyNotContains: []string{"z"}}, resp: []Response{resp(200, "xaxb", nil)}, want: true},
		{name: "body contains forbidden", in: Indicator{BodyNotContains: []string{"a"}}, resp: []Response{resp(200, "xaxb", nil)}, want: false},
		{name: "header present, any case", in: Indicator{HeaderPresent: []string{"location"}}, resp: []Response{resp(302, "", map[string][]string{"Location": {"/"}})}, want: true},
		{name: "header absent holds", in: Indicator{HeaderAbsent: []string{"Location"}}, resp: []Response{resp(200, "", nil)}, want: true},
		{name: "header absent fails", in: Indicator{HeaderAbsent: []string{"Location"}}, resp: []Response{resp(302, "", map[string][]string{"Location": {"/"}})}, want: false},
		{name: "header contains", in: Indicator{HeaderContains: map[string]string{"Location": "invalid"}}, resp: []Response{resp(302, "", map[string][]string{"Location": {"https://example.invalid/x"}})}, want: true},
		{name: "header contains fails", in: Indicator{HeaderContains: map[string]string{"Location": "invalid"}}, resp: []Response{resp(302, "", map[string][]string{"Location": {"/notes"}})}, want: false},
		{name: "cookie without flags", in: Indicator{SetCookieLacks: []string{"HttpOnly", "SameSite"}}, resp: []Response{resp(200, "", cookie("sid=sess-1001; Path=/"))}, want: true},
		{name: "cookie with a flag", in: Indicator{SetCookieLacks: []string{"HttpOnly"}}, resp: []Response{resp(200, "", cookie("sid=sess-1001; Path=/; httponly"))}, want: false},
		{
			name: "cookie steps by one",
			in:   Indicator{CookieIncrement: &CookieIncrement{Name: "sid", Pattern: "sess-([0-9]+)", Step: 1}},
			resp: []Response{resp(200, "", cookie("sid=sess-1001; Path=/")), resp(200, "", cookie("sid=sess-1002; Path=/"))},
			want: true,
		},
		{
			name: "cookie jumps",
			in:   Indicator{CookieIncrement: &CookieIncrement{Name: "sid", Pattern: "sess-([0-9]+)", Step: 1}},
			resp: []Response{resp(200, "", cookie("sid=sess-1001; Path=/")), resp(200, "", cookie("sid=sess-1005; Path=/"))},
			want: false,
		},
		{
			name: "cookie increments needs two responses",
			in:   Indicator{CookieIncrement: &CookieIncrement{Name: "sid", Pattern: "sess-([0-9]+)", Step: 1}},
			resp: []Response{resp(200, "", cookie("sid=sess-1001; Path=/"))},
			want: false,
		},
		{
			name: "cookie without a number",
			in:   Indicator{CookieIncrement: &CookieIncrement{Name: "sid", Pattern: "sess-([0-9]+)", Step: 1}},
			resp: []Response{resp(200, "", cookie("sid=abc; Path=/")), resp(200, "", cookie("sid=abd; Path=/"))},
			want: false,
		},
		{name: "the last response is judged", in: Indicator{Status: 200}, resp: []Response{resp(500, "", nil), resp(200, "", nil)}, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, why := tc.in.Holds(tc.resp)
			if got != tc.want {
				t.Fatalf("Holds = %v (%s), want %v", got, why, tc.want)
			}
			if !got && why == "" {
				t.Fatal("a failed Holds gives no reason")
			}
		})
	}
}

func TestExpandPlaceholders(t *testing.T) {
	got := ExpandPlaceholders("http://127.0.0.1:{console_port}/ and :{port}/", 3000, 3001)
	if want := "http://127.0.0.1:3001/ and :3000/"; got != want {
		t.Fatalf("ExpandPlaceholders = %q, want %q", got, want)
	}
}

func TestApplicabilityCategories(t *testing.T) {
	a := Applicability{
		ExternalEntity: []string{"spoofing", "repudiation"},
		Process:        []string{"spoofing", "tampering", "repudiation", "information_disclosure", "denial_of_service", "elevation_of_privilege"},
		DataStore:      []string{"tampering", "repudiation", "information_disclosure", "denial_of_service"},
		DataFlow:       []string{"tampering", "information_disclosure", "denial_of_service"},
	}
	tests := []struct {
		kind string
		logs bool
		want string
	}{
		{"external_entity", false, "spoofing,repudiation"},
		{"process", false, "spoofing,tampering,repudiation,information_disclosure,denial_of_service,elevation_of_privilege"},
		{"data_store", false, "tampering,information_disclosure,denial_of_service"},
		{"data_store", true, "tampering,repudiation,information_disclosure,denial_of_service"},
		{"data_flow", false, "tampering,information_disclosure,denial_of_service"},
		{"unknown", false, ""},
	}
	for _, tc := range tests {
		if got := strings.Join(a.Categories(tc.kind, tc.logs), ","); got != tc.want {
			t.Errorf("Categories(%s, logs=%v) = %q, want %q", tc.kind, tc.logs, got, tc.want)
		}
	}
}

func TestParseRefusesUnknownFieldAndWrongSchema(t *testing.T) {
	if _, err := ParseManifest([]byte(`{"schema":"x"}`)); err == nil || !strings.Contains(err.Error(), "schema") {
		t.Fatalf("a wrong schema was accepted: %v", err)
	}
	if _, err := ParseManifest([]byte(`{"schema":"` + TruthSchema + `","surprise":1}`)); err == nil {
		t.Fatal("an unknown field was accepted")
	}
	if _, err := ParseThreatModel([]byte(`{"schema":"` + TruthSchema + `"}`)); err == nil {
		t.Fatal("a manifest was accepted as a threat model")
	}
	if _, err := ParseProbes([]byte(`{"schema":"` + ProbesSchema + `"} {}`)); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("trailing data was accepted: %v", err)
	}
}
