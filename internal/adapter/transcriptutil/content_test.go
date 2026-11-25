package transcriptutil

import (
	"encoding/json"
	"reflect"
	"testing"
)

type testBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func textBlock(s string) testBlock { return testBlock{Type: "text", Text: s} }

// TestDecodeContent covers both stored shapes and every input that yields
// nothing.
func TestDecodeContent(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []testBlock
	}{
		{"empty", ``, nil},
		{"whitespace only", " \t\r\n", nil},
		{"array", `[{"type":"text","text":"a"},{"type":"tool_use"}]`, []testBlock{{"text", "a"}, {"tool_use", ""}}},
		{"array with surrounding space", "\n [{\"type\":\"text\",\"text\":\"a\"}] \n", []testBlock{{"text", "a"}}},
		{"empty array", `[]`, []testBlock{}},
		{"bare string", `"hello"`, []testBlock{{"text", "hello"}}},
		{"bare string with leading space", ` "hello"`, []testBlock{{"text", "hello"}}},
		{"object", `{"type":"text"}`, nil},
		{"number", `42`, nil},
		{"null", `null`, nil},
		{"malformed array", `[{"type":`, nil},
		{"malformed string", `"unterminated`, nil},
		{"leading vertical tab", "\v\"x\"", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DecodeContent(json.RawMessage(tc.raw), textBlock)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("DecodeContent(%q) = %#v, want %#v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestTrimJSONSpace trims only the four JSON whitespace bytes.
func TestTrimJSONSpace(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{" \t\r\n", ""},
		{" a ", "a"},
		{"\n\t[1]\r\n", "[1]"},
		{"\va\f", "\va\f"},
		{"a b", "a b"},
	}
	for _, tc := range cases {
		if got := string(TrimJSONSpace([]byte(tc.in))); got != tc.want {
			t.Errorf("TrimJSONSpace(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
