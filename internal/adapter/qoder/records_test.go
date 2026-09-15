package qoder

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestToolResultText(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"bare string", `"File created"`, "File created"},
		{"array of text blocks", `[{"type":"text","text":"line one"},{"type":"text","text":"line two"}]`, "line one\nline two"},
		{"array with empty text skipped", `[{"type":"text","text":""},{"type":"text","text":"kept"}]`, "kept"},
		{"empty", ``, ""},
		{"unknown shape falls back to raw", `{"weird":1}`, `{"weird":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := toolResultText(json.RawMessage(tc.raw)); got != tc.want {
				t.Errorf("toolResultText(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestAuthoredBytes(t *testing.T) {
	cases := []struct {
		name   string
		action string
		input  string
		want   int64
	}{
		{"write content", models.ActionWriteFile, `{"content":"abcde"}`, 5},
		// The Qoder IDE spells Write's body `file_content`.
		{"write file_content (ide)", models.ActionWriteFile, `{"file_content":"abcde","file_path":"/x"}`, 5},
		{"write content wins over file_content", models.ActionWriteFile, `{"content":"abc","file_content":"abcde"}`, 3},
		{"edit new_string", models.ActionEditFile, `{"new_string":"abc"}`, 3},
		{"edit multi", models.ActionEditFile, `{"edits":[{"new_string":"ab"},{"new_string":"cd"}]}`, 4},
		{"run command", models.ActionRunCommand, `{"command":"ls -la"}`, 6},
		{"read is zero", models.ActionReadFile, `{"file_path":"/x"}`, 0},
		{"empty input", models.ActionWriteFile, ``, 0},
		{"malformed input", models.ActionWriteFile, `{not json`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := authoredBytes(tc.action, json.RawMessage(tc.input)); got != tc.want {
				t.Errorf("authoredBytes(%q,%q) = %d, want %d", tc.action, tc.input, got, tc.want)
			}
		})
	}
}

func TestTargetFromInput(t *testing.T) {
	cases := []struct {
		name  string
		input string
		fb    string
		want  string
	}{
		{"file_path", `{"file_path":"/a/b.go"}`, "Read", "/a/b.go"},
		{"command", `{"command":"ls"}`, "Bash", "ls"},
		{"query", `{"query":"needle"}`, "Grep", "needle"},
		{"fallback when no key", `{"unrelated":"x"}`, "Weird", "Weird"},
		{"fallback on empty input", ``, "Fallback", "Fallback"},
		{"fallback on malformed", `{bad`, "Fallback", "Fallback"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := targetFromInput(json.RawMessage(tc.input), tc.fb); got != tc.want {
				t.Errorf("targetFromInput(%q,%q) = %q, want %q", tc.input, tc.fb, got, tc.want)
			}
		})
	}
}

func TestParseTimestamp(t *testing.T) {
	if !parseTimestamp("").IsZero() {
		t.Error("empty timestamp should be zero")
	}
	if !parseTimestamp("not-a-time").IsZero() {
		t.Error("unparseable timestamp should be zero")
	}
	got := parseTimestamp("2026-07-09T04:54:27.199Z")
	if got.IsZero() {
		t.Fatal("RFC3339 timestamp failed to parse")
	}
	// segment offset form.
	off := parseTimestamp("2026-07-09T10:24:32.438+05:30")
	if off.IsZero() {
		t.Fatal("offset timestamp failed to parse")
	}
	if off.Location() != time.UTC {
		t.Errorf("timestamp not normalized to UTC: %v", off.Location())
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("hello", 10); got != "hello" {
		t.Errorf("truncate short = %q", got)
	}
	if got := truncate("hello", 3); got != "hel" {
		t.Errorf("truncate long = %q", got)
	}
}

func TestToolEventIDFallback(t *testing.T) {
	if got := toolEventID("call_x", "u", 0); got != "call_x" {
		t.Errorf("toolEventID with id = %q, want call_x", got)
	}
	if got := toolEventID("", "u-2", 3); got != "u-2:3" {
		t.Errorf("toolEventID fallback = %q, want u-2:3", got)
	}
}

func TestSegTokenIDFallback(t *testing.T) {
	if got := segTokenID(rawSegment{RequestID: "req-1"}, 5); got != "tok:req-1" {
		t.Errorf("segTokenID with request = %q", got)
	}
	if got := segTokenID(rawSegment{TurnID: "turn-1"}, 5); got != "tok:turn-1:5" {
		t.Errorf("segTokenID fallback = %q, want tok:turn-1:5", got)
	}
}

func TestSessionIDFromSegmentPath(t *testing.T) {
	p := "/home/u/.qoder/logs/sessions/-home-dev-proj/the-sid/segments/seg.jsonl"
	if got := sessionIDFromSegmentPath(p); got != "the-sid" {
		t.Errorf("sessionIDFromSegmentPath = %q, want the-sid", got)
	}
	// The file must sit directly under a `segments/` dir; anything else
	// yields "" (the token event then carries the empty session id, but
	// that shape never occurs for a real run-log).
	if got := sessionIDFromSegmentPath("/no/segments/here/x.jsonl"); got != "" {
		t.Errorf("sessionIDFromSegmentPath deep = %q, want empty", got)
	}
	if got := sessionIDFromSegmentPath("/not/a/segment/x.jsonl"); got != "" {
		t.Errorf("sessionIDFromSegmentPath non-segment = %q, want empty", got)
	}
}

func TestFlexTimestampNumericAndString(t *testing.T) {
	cases := []struct {
		name string
		line string
		want time.Time
	}{
		// The Windows v1.0.40 capture mixes bare epoch numbers into files
		// whose other lines carry RFC3339 strings — a numeric line must
		// decode, not fail the record as malformed JSON.
		{"epoch millis", `{"timestamp":1767950658770}`, time.UnixMilli(1767950658770).UTC()},
		{"epoch seconds", `{"timestamp":1767950658}`, time.Unix(1767950658, 0).UTC()},
		{"rfc3339 string", `{"timestamp":"2026-07-09T10:24:18.770Z"}`, time.Date(2026, 7, 9, 10, 24, 18, 770e6, time.UTC)},
		{"null", `{"timestamp":null}`, time.Time{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var rec rawRecord
			if err := json.Unmarshal([]byte(tc.line), &rec); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got := parseTimestamp(rec.Timestamp); !got.Equal(tc.want) {
				t.Errorf("parseTimestamp = %v, want %v", got, tc.want)
			}
		})
	}
}
