package statusline

import (
	"testing"
)

func strPtr(s string) *string   { return &s }
func f64Ptr(v float64) *float64 { return &v }

func TestParseInputFullShape(t *testing.T) {
	data := []byte(`{
		"session_id": "sess-123",
		"transcript_path": "/tmp/transcript.jsonl",
		"cwd": "/home/user/project",
		"model": {"id": "claude-opus-4-5-20260101", "display_name": "claude-opus-4-5"},
		"workspace": {"current_dir": "/home/user/project", "project_dir": "/home/user/project"},
		"cost": {"total_cost_usd": 3.42, "total_duration_ms": 60000, "total_lines_added": 12, "total_lines_removed": 4},
		"output_style": "default",
		"version": "1.28.0"
	}`)

	in, err := ParseInput(data)
	if err != nil {
		t.Fatalf("ParseInput: %v", err)
	}

	switch {
	case in.SessionID == nil || *in.SessionID != "sess-123":
		t.Errorf("SessionID = %v, want sess-123", in.SessionID)
	case in.TranscriptPath == nil || *in.TranscriptPath != "/tmp/transcript.jsonl":
		t.Errorf("TranscriptPath = %v", in.TranscriptPath)
	case in.CWD == nil || *in.CWD != "/home/user/project":
		t.Errorf("CWD = %v", in.CWD)
	}

	if in.Model == nil {
		t.Fatal("Model is nil")
	}
	if in.Model.ID == nil || *in.Model.ID != "claude-opus-4-5-20260101" {
		t.Errorf("Model.ID = %v", in.Model.ID)
	}
	if in.Model.DisplayName == nil || *in.Model.DisplayName != "claude-opus-4-5" {
		t.Errorf("Model.DisplayName = %v", in.Model.DisplayName)
	}

	if in.Workspace == nil {
		t.Fatal("Workspace is nil")
	}
	if in.Workspace.CurrentDir == nil || *in.Workspace.CurrentDir != "/home/user/project" {
		t.Errorf("Workspace.CurrentDir = %v", in.Workspace.CurrentDir)
	}
	if in.Workspace.ProjectDir == nil || *in.Workspace.ProjectDir != "/home/user/project" {
		t.Errorf("Workspace.ProjectDir = %v", in.Workspace.ProjectDir)
	}

	if in.Cost == nil {
		t.Fatal("Cost is nil")
	}
	if in.Cost.TotalCostUSD == nil || *in.Cost.TotalCostUSD != 3.42 {
		t.Errorf("Cost.TotalCostUSD = %v", in.Cost.TotalCostUSD)
	}
	if in.Cost.TotalDurationMS == nil || *in.Cost.TotalDurationMS != 60000 {
		t.Errorf("Cost.TotalDurationMS = %v", in.Cost.TotalDurationMS)
	}
	if in.Cost.TotalLinesAdded == nil || *in.Cost.TotalLinesAdded != 12 {
		t.Errorf("Cost.TotalLinesAdded = %v", in.Cost.TotalLinesAdded)
	}
	if in.Cost.TotalLinesRemoved == nil || *in.Cost.TotalLinesRemoved != 4 {
		t.Errorf("Cost.TotalLinesRemoved = %v", in.Cost.TotalLinesRemoved)
	}

	if in.OutputStyle == nil || *in.OutputStyle != "default" {
		t.Errorf("OutputStyle = %v", in.OutputStyle)
	}
	if in.Version == nil || *in.Version != "1.28.0" {
		t.Errorf("Version = %v", in.Version)
	}
}

func TestParseInputMissingOptionals(t *testing.T) {
	// Only session_id present — every other field must come back nil,
	// never a fabricated zero value.
	data := []byte(`{"session_id": "sess-only"}`)

	in, err := ParseInput(data)
	if err != nil {
		t.Fatalf("ParseInput: %v", err)
	}
	if in.SessionID == nil || *in.SessionID != "sess-only" {
		t.Errorf("SessionID = %v, want sess-only", in.SessionID)
	}
	if in.Model != nil {
		t.Errorf("Model = %+v, want nil", in.Model)
	}
	if in.Workspace != nil {
		t.Errorf("Workspace = %+v, want nil", in.Workspace)
	}
	if in.Cost != nil {
		t.Errorf("Cost = %+v, want nil", in.Cost)
	}
	if in.OutputStyle != nil {
		t.Errorf("OutputStyle = %v, want nil", in.OutputStyle)
	}
}

func TestParseInputPartialNestedObject(t *testing.T) {
	// cost is present but only carries total_cost_usd — the other three
	// cost sub-fields must stay nil, not zero.
	data := []byte(`{"cost": {"total_cost_usd": 1.5}}`)

	in, err := ParseInput(data)
	if err != nil {
		t.Fatalf("ParseInput: %v", err)
	}
	if in.Cost == nil {
		t.Fatal("Cost is nil")
	}
	if in.Cost.TotalCostUSD == nil || *in.Cost.TotalCostUSD != 1.5 {
		t.Errorf("Cost.TotalCostUSD = %v", in.Cost.TotalCostUSD)
	}
	if in.Cost.TotalDurationMS != nil {
		t.Errorf("Cost.TotalDurationMS = %v, want nil", in.Cost.TotalDurationMS)
	}
	if in.Cost.TotalLinesAdded != nil {
		t.Errorf("Cost.TotalLinesAdded = %v, want nil", in.Cost.TotalLinesAdded)
	}
	if in.Cost.TotalLinesRemoved != nil {
		t.Errorf("Cost.TotalLinesRemoved = %v, want nil", in.Cost.TotalLinesRemoved)
	}
}

func TestParseInputUnknownFieldsIgnored(t *testing.T) {
	// An unrecognized top-level key and an unrecognized nested key must
	// not cause an error — tolerant per ParseInput's doc comment.
	data := []byte(`{
		"session_id": "sess-x",
		"some_future_field": {"nested": true},
		"model": {"id": "gpt-99", "some_future_model_field": 42}
	}`)

	in, err := ParseInput(data)
	if err != nil {
		t.Fatalf("ParseInput: %v", err)
	}
	if in.SessionID == nil || *in.SessionID != "sess-x" {
		t.Errorf("SessionID = %v", in.SessionID)
	}
	if in.Model == nil || in.Model.ID == nil || *in.Model.ID != "gpt-99" {
		t.Errorf("Model = %+v", in.Model)
	}
}

func TestParseInputMalformedJSON(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"truncated object", []byte(`{"session_id": "sess-123", "model": {`)},
		{"trailing garbage", []byte(`{"session_id": "sess-123"} garbage`)},
		{"empty input", []byte(``)},
		{"non-json plain text", []byte(`hello, this is not json at all`)},
		{"json array not object", []byte(`["not", "an", "object"]`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in, err := ParseInput(tt.data)
			if err == nil {
				t.Fatalf("ParseInput(%q) returned no error, want one", tt.data)
			}
			// The caller must still get a usable zero Input, never a
			// panic and never a partially-populated struct claiming
			// data it doesn't have.
			if in.SessionID != nil || in.Model != nil || in.Cost != nil {
				t.Errorf("ParseInput on malformed input returned non-nil fields: %+v", in)
			}
		})
	}
}

// TestParsePayloadShapes is the table of host payload shapes: each row is
// an anonymized payload in the shape its host's source builds (Claude
// Code, CodeBuddy 2.171.0 collectStatusLineData, Kimchi 1.17.0
// buildScriptPayload, VT Code 0.180.2 StatusLineCommandPayload) and what
// the normalized Input must carry. An absent datum stays nil.
func TestParsePayloadShapes(t *testing.T) {
	type want struct {
		shape      Shape
		session    *string
		transcript *string
		cost       *float64
		model      *string // display name
		modelID    *string
		cwd        *string
		style      *string
	}
	cases := []struct {
		name string
		data string
		want want
	}{
		{
			name: "claude code, output_style object",
			data: `{"hook_event_name":"Status","session_id":"s-1","transcript_path":"/home/u/.claude/projects/p/s-1.jsonl","cwd":"/home/u/p",
				"model":{"id":"claude-opus-4-5","display_name":"Opus"},"workspace":{"current_dir":"/home/u/p","project_dir":"/home/u/p"},
				"version":"2.1.0","output_style":{"name":"default"},"cost":{"total_cost_usd":0.5,"total_duration_ms":10},
				"rate_limits":{"five_hour":{"used_percentage":12}}}`,
			want: want{shape: ShapeClaude, session: strPtr("s-1"), transcript: strPtr("/home/u/.claude/projects/p/s-1.jsonl"), cost: f64Ptr(0.5), model: strPtr("Opus"), modelID: strPtr("claude-opus-4-5"), cwd: strPtr("/home/u/p"), style: strPtr("default")},
		},
		{
			name: "codebuddy",
			data: `{"hook_event_name":"Status","session_id":"cb-1","session_name":"x","transcript_path":"/home/u/.codebuddy/projects/p/cb-1.jsonl","cwd":"/home/u/p",
				"permission_mode":"default","model":{"id":"hy4-preview","display_name":"HY4"},"workspace":{"current_dir":"/home/u/p","project_dir":"/home/u/p","added_dirs":[]},
				"version":"2.171.0","output_style":{"name":"default"},"cost":{"total_cost_usd":0.25},"context_window":{"context_window_size":200000},"exceeds_200k_tokens":false}`,
			want: want{shape: ShapeClaude, session: strPtr("cb-1"), transcript: strPtr("/home/u/.codebuddy/projects/p/cb-1.jsonl"), cost: f64Ptr(0.25), model: strPtr("HY4"), modelID: strPtr("hy4-preview"), cwd: strPtr("/home/u/p"), style: strPtr("default")},
		},
		{
			name: "codebuddy with no session: the unknown placeholder is not an id",
			data: `{"hook_event_name":"Status","session_id":"unknown","cwd":"/home/u/p","model":{"id":"hy4-preview","display_name":"HY4"}}`,
			want: want{shape: ShapeClaude, model: strPtr("HY4"), modelID: strPtr("hy4-preview"), cwd: strPtr("/home/u/p")},
		},
		{
			name: "kimchi nested session",
			data: `{"model":{"id":"kimi-k2.5","name":"Kimi K2.5"},"context":{"used":100,"limit":1000,"percent":10},"credits":"$4.20","budget":"$10.00",
				"workspace":{"cwd":"/home/u/p","current_dir":"/home/u/p"},"status":"idle",
				"session":{"cost_usd":0.75,"last_turn":null,"id":"019a0000-0000-7000-8000-000000000001","name":null,"transcript_path":"/home/u/.config/kimchi/harness/sessions/p/s.jsonl"},
				"cost":{"total_cost_usd":0.75,"total_duration_ms":1000,"total_lines_added":0,"total_lines_removed":0},"phase":"build"}`,
			want: want{shape: ShapeNestedSession, session: strPtr("019a0000-0000-7000-8000-000000000001"), transcript: strPtr("/home/u/.config/kimchi/harness/sessions/p/s.jsonl"), cost: f64Ptr(0.75), model: strPtr("Kimi K2.5"), modelID: strPtr("kimi-k2.5")},
		},
		{
			name: "kimchi before a model is chosen",
			data: `{"model":{"id":null,"name":null},"workspace":{"cwd":"/home/u/p","current_dir":"/home/u/p"},"session":{"cost_usd":0,"id":"s-k"},"cost":{"total_cost_usd":0}}`,
			want: want{shape: ShapeNestedSession, session: strPtr("s-k"), cost: f64Ptr(0)},
		},
		{
			name: "vtcode no session, no cost",
			data: `{"hook_event_name":"Status","cwd":"/home/u/p","workspace":{"current_dir":"/home/u/p","project_dir":"/home/u/p","dominant_language":"Go","active_language":"Go"},
				"model":{"id":"gpt-5.5","display_name":"GPT-5.5"},"runtime":{"reasoning_effort":"medium"},"git":{"branch":"main","dirty":false},"version":"0.180.2"}`,
			want: want{shape: ShapeNoSession, model: strPtr("GPT-5.5"), modelID: strPtr("gpt-5.5"), cwd: strPtr("/home/u/p")},
		},
		{
			name: "a mistyped field is dropped alone",
			data: `{"session_id":"s-2","cost":"not-an-object","model":{"id":"m"},"output_style":42}`,
			want: want{shape: ShapeClaude, session: strPtr("s-2"), modelID: strPtr("m")},
		},
	}
	eq := func(a, b *string) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in, shape, err := ParsePayload([]byte(c.data))
			if err != nil {
				t.Fatalf("ParsePayload: %v", err)
			}
			if shape != c.want.shape {
				t.Errorf("shape = %q, want %q", shape, c.want.shape)
			}
			if !eq(in.SessionID, c.want.session) {
				t.Errorf("SessionID = %v, want %v", deref(in.SessionID), deref(c.want.session))
			}
			if !eq(in.TranscriptPath, c.want.transcript) {
				t.Errorf("TranscriptPath = %v, want %v", deref(in.TranscriptPath), deref(c.want.transcript))
			}
			var cost *float64
			if in.Cost != nil {
				cost = in.Cost.TotalCostUSD
			}
			if (cost == nil) != (c.want.cost == nil) || (cost != nil && *cost != *c.want.cost) {
				t.Errorf("cost = %v, want %v", cost, c.want.cost)
			}
			var dn, id *string
			if in.Model != nil {
				dn, id = in.Model.DisplayName, in.Model.ID
			}
			if !eq(dn, c.want.model) || !eq(id, c.want.modelID) {
				t.Errorf("model = %v/%v, want %v/%v", deref(dn), deref(id), deref(c.want.model), deref(c.want.modelID))
			}
			if !eq(in.CWD, c.want.cwd) {
				t.Errorf("CWD = %v, want %v", deref(in.CWD), deref(c.want.cwd))
			}
			if !eq(in.OutputStyle, c.want.style) {
				t.Errorf("OutputStyle = %v, want %v", deref(in.OutputStyle), deref(c.want.style))
			}
		})
	}
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}
