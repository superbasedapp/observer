package secassess

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The golden table both decoders are run against: this package's jsonUnescape
// (what the evidence check reads a body through) and the dashboard's
// jsonUnescapeOnce (web/src/lib/secAssessModel.ts, what a stored condition is
// shown through). One file, so the two cannot drift apart without a test failing
// on one side (N-14).
type unescapeCase struct {
	Name string `json:"name"`
	In   string `json:"in"`
	Want string `json:"want"`
}

func readUnescapeCases(t *testing.T) []unescapeCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/json_unescape_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []unescapeCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 15 {
		t.Fatalf("the golden table holds %d cases, expected the full set", len(cases))
	}
	return cases
}

func TestJSONUnescapeGoldenTable(t *testing.T) {
	for _, c := range readUnescapeCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			if got := jsonUnescape(c.In); got != c.Want {
				t.Errorf("jsonUnescape(%q) = %q, want %q", c.In, got, c.Want)
			}
		})
	}
}

// TestMatchWordsShowsTheTextNotItsEncoding (N-14): a stored condition written
// inside a JSON string (a quote as backslash-quote) is shown as the text it
// means, in plain quotes, where the task's line (matchWords) keeps the Go string
// form the agent is told to read.
func TestMatchWordsShowsTheTextNotItsEncoding(t *testing.T) {
	bs := string(rune(92))
	stored := bs + `"role` + bs + `": ` + bs + `"admin` + bs + `"`
	cases := []struct {
		name      string
		m         *PTMatch
		display   string
		taskLine  string
		taskKeeps bool
	}{
		{
			"a body text with escaped quotes",
			&PTMatch{BodyContains: []string{stored}},
			`body contains ""role": "admin""`,
			`body contains "` + bs + bs + bs + `"role` + bs + bs + bs + `": ` + bs + bs + bs + `"admin` + bs + bs + bs + `""`,
			true,
		},
		{
			"a text without an escape is the same in both",
			&PTMatch{BodyContains: []string{"admin"}, BodyNotContains: []string{"denied"}},
			`body contains "admin"; body lacks "denied"`,
			`body contains "admin"; body lacks "denied"`,
			false,
		},
		{
			"a header value",
			&PTMatch{HeaderContains: []PTHeader{{Name: "Set-Cookie", Value: bs + `"x` + bs + `"`}}},
			`header Set-Cookie contains ""x""`,
			"",
			false,
		},
		{
			"a newline escape shows as the line break it is, then is cleaned to one line",
			&PTMatch{BodyContains: []string{"a" + bs + "nb"}},
			`body contains "a b"`,
			"",
			false,
		},
		{
			"a status and a presence are not quoted",
			&PTMatch{Status: 403, HeaderPresent: []string{"X-A"}, HeaderAbsent: []string{"X-B"}},
			"status 403; header X-A present; header X-B absent",
			"status 403; header X-A present; header X-B absent",
			false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := MatchWords(c.m)
			if got != c.display {
				t.Errorf("MatchWords = %q, want %q", got, c.display)
			}
			if strings.Contains(got, bs+`"`) {
				t.Errorf("the display line still carries an escaped quote: %q", got)
			}
			if c.taskLine != "" {
				if task := matchWords(c.m); task != c.taskLine {
					t.Errorf("matchWords (the task's line) = %q, want %q", task, c.taskLine)
				}
			}
			// The two lines say the same conditions in the same order.
			if c.taskKeeps && matchWords(c.m) == got {
				t.Error("the task line and the display line should differ for an escaped text")
			}
		})
	}
}
