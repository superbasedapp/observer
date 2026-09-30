package alignment

import (
	"reflect"
	"testing"
)

func TestParseResultBareJSON(t *testing.T) {
	raw := `{"delivered":["retry logic"],"missed":["backoff jitter"],"extra":[],"confidence":0.8,"notes":"solid"}`
	got, err := ParseResult(raw)
	if err != nil {
		t.Fatalf("ParseResult: %v", err)
	}
	want := Result{
		Delivered:  []string{"retry logic"},
		Missed:     []string{"backoff jitter"},
		Extra:      []string{},
		Confidence: 0.8,
		Notes:      "solid",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseResult(bare) = %+v, want %+v", got, want)
	}
}

func TestParseResultFencedJSON(t *testing.T) {
	raw := "Here is my verdict:\n```json\n{\"delivered\":[\"a\"],\"missed\":[],\"extra\":[\"b\"],\"confidence\":0.5,\"notes\":\"ok\"}\n```\nLet me know if you need more detail."
	got, err := ParseResult(raw)
	if err != nil {
		t.Fatalf("ParseResult: %v", err)
	}
	if len(got.Delivered) != 1 || got.Delivered[0] != "a" {
		t.Fatalf("ParseResult(fenced).Delivered = %v", got.Delivered)
	}
	if len(got.Extra) != 1 || got.Extra[0] != "b" {
		t.Fatalf("ParseResult(fenced).Extra = %v", got.Extra)
	}
	if got.Confidence != 0.5 {
		t.Fatalf("ParseResult(fenced).Confidence = %v, want 0.5", got.Confidence)
	}
}

func TestParseResultFencedNoLanguageTag(t *testing.T) {
	raw := "```\n{\"delivered\":[],\"missed\":[\"x\"],\"extra\":[],\"confidence\":1,\"notes\":\"\"}\n```"
	got, err := ParseResult(raw)
	if err != nil {
		t.Fatalf("ParseResult: %v", err)
	}
	if len(got.Missed) != 1 || got.Missed[0] != "x" {
		t.Fatalf("ParseResult(fenced-no-tag).Missed = %v", got.Missed)
	}
}

func TestParseResultTrailingProse(t *testing.T) {
	raw := `{"delivered":["thing"],"missed":[],"extra":[],"confidence":0.9,"notes":"n"} That should cover it, let me know if you have questions!`
	got, err := ParseResult(raw)
	if err != nil {
		t.Fatalf("ParseResult: %v", err)
	}
	if len(got.Delivered) != 1 || got.Delivered[0] != "thing" {
		t.Fatalf("ParseResult(trailing prose).Delivered = %v", got.Delivered)
	}
}

func TestParseResultLeadingProse(t *testing.T) {
	raw := `Sure, here's the verdict: {"delivered":["thing"],"missed":[],"extra":[],"confidence":0.3,"notes":"n"}`
	got, err := ParseResult(raw)
	if err != nil {
		t.Fatalf("ParseResult: %v", err)
	}
	if got.Confidence != 0.3 {
		t.Fatalf("ParseResult(leading prose).Confidence = %v, want 0.3", got.Confidence)
	}
}

func TestParseResultConfidenceClamped(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want float64
	}{
		{"above one", `{"delivered":[],"missed":[],"extra":[],"confidence":1.7,"notes":""}`, 1},
		{"below zero", `{"delivered":[],"missed":[],"extra":[],"confidence":-0.4,"notes":""}`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseResult(c.raw)
			if err != nil {
				t.Fatalf("ParseResult: %v", err)
			}
			if got.Confidence != c.want {
				t.Fatalf("Confidence = %v, want %v", got.Confidence, c.want)
			}
		})
	}
}

func TestParseResultGarbageErrors(t *testing.T) {
	cases := []string{
		"",
		"   ",
		"the model refused to answer in JSON at all",
		"{\"delivered\": [\"unterminated", // unbalanced braces
	}
	for _, raw := range cases {
		if _, err := ParseResult(raw); err == nil {
			t.Errorf("ParseResult(%q) succeeded, want an error", raw)
		}
	}
}

func TestParseResultBraceInsideString(t *testing.T) {
	// A literal '{' inside a JSON string value must not confuse the
	// brace-balance scanner into closing early.
	raw := `{"delivered":["renders {curly} placeholders correctly"],"missed":[],"extra":[],"confidence":0.6,"notes":""}`
	got, err := ParseResult(raw)
	if err != nil {
		t.Fatalf("ParseResult: %v", err)
	}
	if len(got.Delivered) != 1 || got.Delivered[0] != "renders {curly} placeholders correctly" {
		t.Fatalf("ParseResult(brace-in-string).Delivered = %v", got.Delivered)
	}
}
