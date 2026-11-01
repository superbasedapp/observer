package jsoncompat

import (
	"strings"
	"testing"
	"time"
)

// TestVariantsRewriteTheBytes pins the byte-level rewrites the golden
// checks rely on: each named rewrite produces exactly this body.
func TestVariantsRewriteTheBytes(t *testing.T) {
	t.Parallel()
	body := []byte(`{"session_id": "s1", "tool_input": {"command": "ls"}}`)
	got := map[string]string{}
	for _, v := range Variants(body, nil) {
		if _, dup := got[v.Name]; dup {
			t.Fatalf("variant %q listed twice", v.Name)
		}
		got[v.Name] = string(v.Body)
	}
	want := map[string]string{
		"as-is":                                    `{"session_id": "s1", "tool_input": {"command": "ls"}}`,
		"session_id: duplicate, last wins":         `{"session_id": "s1", "tool_input": {"command": "ls"},"session_id":"dup-last"}`,
		"session_id: duplicate, earlier loses":     `{"session_id":"dup-first","session_id": "s1", "tool_input": {"command": "ls"}}`,
		"session_id: missing":                      `{"tool_input": {"command": "ls"}}`,
		"tool_input: missing":                      `{"session_id": "s1"}`,
		"session_id: key camelCase":                `{"sessionId": "s1", "tool_input": {"command": "ls"}}`,
		"session_id: key Unicode case folding":     "{\"\u017fe\u017f\u017fion_id\": \"s1\", \"tool_input\": {\"command\": \"ls\"}}",
		"session_id: key first byte escaped":       `{"\u0073ession_id": "s1", "tool_input": {"command": "ls"}}`,
		"session_id: value float overflow":         `{"session_id": 1e400, "tool_input": {"command": "ls"}}`,
		"session_id: string invalid UTF-8":         "{\"session_id\": \"s1\xff\xfe\", \"tool_input\": {\"command\": \"ls\"}}",
		"tool_input.command: duplicate, last wins": `{"session_id": "s1", "tool_input": {"command": "ls","command":"dup-last"}}`,
		"tool_input.command: value null":           `{"session_id": "s1", "tool_input": {"command": null}}`,
		"tool_input.command: key upper-case":       `{"session_id": "s1", "tool_input": {"COMMAND": "ls"}}`,
		"every top-level key upper-case":           `{"SESSION_ID": "s1", "TOOL_INPUT": {"command": "ls"}}`,
	}
	for name, body := range want {
		if got[name] != body {
			t.Errorf("%s:\n got %q\nwant %q", name, got[name], body)
		}
	}
	// The nested set is the smaller one.
	if _, ok := got["tool_input.command: key title-case"]; ok {
		t.Error("a nested member got the full key rename set")
	}
}

// TestVariantsRepeatSet pins the short set for a field name an earlier
// payload already received the full set for.
func TestVariantsRepeatSet(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	first := Variants([]byte(`{"a":"x"}`), seen)
	second := Variants([]byte(`{"a":"y"}`), seen)
	count := func(vs []Variant) int {
		n := 0
		for _, v := range vs {
			if strings.HasPrefix(v.Name, "a: ") {
				n++
			}
		}
		return n
	}
	if count(second) != len(repeatSet) || count(first) <= count(second) {
		t.Fatalf("member variants: first %d, second %d, want the second to be the %d-entry repeat set", count(first), count(second), len(repeatSet))
	}
}

// TestVariantsOfANonObject keeps only the whole-body rewrites.
func TestVariantsOfANonObject(t *testing.T) {
	t.Parallel()
	for _, v := range Variants([]byte(`[1,2]`), nil) {
		if strings.Contains(v.Name, ": ") {
			t.Fatalf("member rewrite %q of a non-object", v.Name)
		}
	}
}

// TestDump pins the deterministic rendering.
func TestDump(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	type inner struct {
		When   time.Time
		Old    time.Time
		Err    error
		hidden string
	}
	got := Dump(map[string]any{
		"b": []byte("x"),
		"a": &inner{When: now.Add(time.Minute), Old: now.Add(-48 * time.Hour), Err: errFixture{}, hidden: "h"},
		"c": "id:" + now.Format(time.RFC3339Nano),
		"d": []any{nil, 1.5, true},
	}, now)
	want := `map{"a": &jsoncompat.inner{When: time(now), Old: time(2026-10-18T12:00:00Z), Err: error}, "b": bytes"x", "c": "id:(now)", "d": [nil, 1.5, true]}`
	if got != want {
		t.Fatalf("Dump:\n got %s\nwant %s", got, want)
	}
}

type errFixture struct{}

func (errFixture) Error() string { return "boom" }
