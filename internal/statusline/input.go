package statusline

import (
	"encoding/json"
	"fmt"
)

// Input is the normalized status-line payload: Claude Code's statusLine stdin-JSON
// contract (plan §1.1, §6.1 "Critical files": session_id,
// transcript_path, cwd, model.{id,display_name},
// workspace.{current_dir,project_dir},
// cost.{total_cost_usd,total_duration_ms,total_lines_added,
// total_lines_removed}, output_style, version).
//
// Every field is a pointer, and every nested group is a pointer to its
// own struct, so an ABSENT field is representable as nil rather than
// coerced into a fabricated zero value (a float64 cost of 0 and an absent
// cost are different facts; only ParseInput's caller — the segment
// renderers in segments.go — gets to decide what an absent datum means
// for the rendered line, and they decide "omit the segment," never
// "print zero"). The json tags below are Claude Code's wire contract;
// ParsePayload decodes each field on its own and maps the other hosts'
// shapes (payloadShapes) onto the same struct.
type Input struct {
	// SessionID is Claude Code's session identifier for this statusLine
	// invocation, when present.
	SessionID *string `json:"session_id"`
	// TranscriptPath is the path to the session's transcript file, when
	// present. Never used to source a segment today, but kept because
	// the documented contract carries it.
	TranscriptPath *string `json:"transcript_path"`
	// CWD is the top-level "cwd" field some Claude Code versions carry
	// alongside (or instead of) Workspace.CurrentDir.
	CWD *string `json:"cwd"`
	// Model carries the current model's id/display name, when the host
	// supplied a "model" object at all.
	Model *Model `json:"model"`
	// Workspace carries the current/project directory, when the host
	// supplied a "workspace" object at all.
	Workspace *Workspace `json:"workspace"`
	// Cost carries the session's accumulated cost/duration/line-count
	// figures, when the host supplied a "cost" object at all.
	Cost *Cost `json:"cost"`
	// OutputStyle is Claude Code's active output-style name, when
	// present.
	OutputStyle *string `json:"output_style"`
	// Version is the reporting Claude Code version string, when present.
	Version *string `json:"version"`
}

// Model is the "model" object of the statusLine stdin-JSON payload.
type Model struct {
	// ID is the model's raw identifier (e.g. "claude-opus-4-5-20260101").
	ID *string `json:"id"`
	// DisplayName is the model's human-friendly name (e.g.
	// "claude-opus-4-5"), preferred over ID when both are present
	// (segments.go).
	DisplayName *string `json:"display_name"`
}

// Workspace is the "workspace" object of the statusLine stdin-JSON
// payload.
type Workspace struct {
	// CurrentDir is the directory Claude Code is currently running in.
	CurrentDir *string `json:"current_dir"`
	// ProjectDir is the resolved project root, when Claude Code was able
	// to determine one.
	ProjectDir *string `json:"project_dir"`
}

// Cost is the "cost" object of the statusLine stdin-JSON payload —
// figures Claude Code has already computed server-side for this session,
// no lookup required to render them (plan §1.1, §4.1).
type Cost struct {
	// TotalCostUSD is the session's accumulated observed spend, in US
	// dollars.
	TotalCostUSD *float64 `json:"total_cost_usd"`
	// TotalDurationMS is the session's accumulated wall-clock duration,
	// in milliseconds.
	TotalDurationMS *int64 `json:"total_duration_ms"`
	// TotalLinesAdded is the session's accumulated added-line count.
	TotalLinesAdded *int64 `json:"total_lines_added"`
	// TotalLinesRemoved is the session's accumulated removed-line count.
	TotalLinesRemoved *int64 `json:"total_lines_removed"`
}

// Shape names the payload shape ParsePayload detected, so a caller can say
// which host contract it read (`observer statusline --explain`).
type Shape string

// Detected payload shapes (payloadShapes, first match wins).
const (
	// ShapeClaude is Claude Code's top-level shape, which CodeBuddy's
	// payload also follows (plus context_window and a few extra keys).
	ShapeClaude Shape = "claude"
	// ShapeNestedSession is Kimchi's: no top-level session_id, the session
	// id and transcript path nested under session{}, and model.name in place
	// of model.display_name. Its top-level cost.total_cost_usd is read as is.
	ShapeNestedSession Shape = "nested-session"
	// ShapeNoSession is VT Code's StatusLineCommandPayload: hook_event_name
	// "Status", cwd, workspace, model and runtime, with no session id and no
	// cost at all, so the session segment is honestly omitted.
	ShapeNoSession Shape = "no-session"
)

// payloadProbe is the handful of keys that tell the shapes apart and the
// fields a non-Claude shape carries somewhere else.
type payloadProbe struct {
	HookEventName string          `json:"hook_event_name"`
	SessionID     json.RawMessage `json:"session_id"`
	Runtime       json.RawMessage `json:"runtime"`
	Session       *struct {
		ID             *string `json:"id"`
		TranscriptPath *string `json:"transcript_path"`
	} `json:"session"`
	Model *struct {
		Name *string `json:"name"`
	} `json:"model"`
}

// payloadShape is one row of the shape table: a test on the probe and the
// normalization that maps the shape onto Input.
type payloadShape struct {
	shape     Shape
	match     func(p payloadProbe) bool
	normalize func(in *Input, p payloadProbe)
}

// payloadShapes is walked top-down; the last row (Claude's) always matches.
var payloadShapes = []payloadShape{
	{
		shape: ShapeNestedSession,
		match: func(p payloadProbe) bool {
			return len(p.SessionID) == 0 && p.Session != nil && p.Session.ID != nil
		},
		normalize: func(in *Input, p payloadProbe) {
			in.SessionID = p.Session.ID
			if in.TranscriptPath == nil {
				in.TranscriptPath = p.Session.TranscriptPath
			}
			if p.Model != nil && p.Model.Name != nil && in.Model != nil && in.Model.DisplayName == nil {
				in.Model.DisplayName = p.Model.Name
			}
		},
	},
	{
		shape: ShapeNoSession,
		match: func(p payloadProbe) bool {
			return len(p.SessionID) == 0 && p.HookEventName == "Status" && len(p.Runtime) > 0
		},
		normalize: func(in *Input, _ payloadProbe) {
			// No session id and no cost exist in this shape: whatever a
			// look-alike key decoded to is not this host's figure.
			in.SessionID, in.Cost = nil, nil
		},
	},
	{
		shape: ShapeClaude,
		match: func(payloadProbe) bool { return true },
		normalize: func(in *Input, _ payloadProbe) {
			// CodeBuddy sends session_id "unknown" when no session exists:
			// a placeholder, not an id.
			if in.SessionID != nil && *in.SessionID == "unknown" {
				in.SessionID = nil
			}
		},
	},
}

// ParseInput decodes a status-line stdin-JSON payload (any shape
// ParsePayload knows) into Input.
//
// It is deliberately tolerant: unknown top-level or nested fields are
// silently ignored, a known field whose JSON type is not the expected one
// is dropped on its own (it never voids the rest of the payload), and any
// field the payload DOES supply is kept even when others are missing (a
// payload with only "session_id" yields an Input with SessionID set and
// every other field nil).
//
// When data is not a JSON object at all (malformed, truncated, or piped
// from something that isn't a status-line host), ParseInput returns a
// non-nil error AND a usable zero-value Input — the caller is never forced
// to treat a parse failure as fatal; it can render the degraded
// wordmark-only line and move on (plan §2.3's fail-open contract extends
// to this parse step, not just the daemon HTTP path).
func ParseInput(data []byte) (Input, error) {
	in, _, err := ParsePayload(data)
	return in, err
}

// ParsePayload is ParseInput that also reports the detected Shape. The
// shape is detected from the payload alone (payloadShapes, table-driven)
// and normalized onto the one Input the renderer reads, so the renderer
// never learns which host sent it.
func ParsePayload(data []byte) (Input, Shape, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return Input{}, "", fmt.Errorf("statusline.ParsePayload: %w", err)
	}
	var in Input
	field := func(key string, dst any) {
		if raw, ok := top[key]; ok {
			// A mistyped field is dropped alone; the others still decode.
			_ = json.Unmarshal(raw, dst)
		}
	}
	field("session_id", &in.SessionID)
	field("transcript_path", &in.TranscriptPath)
	field("cwd", &in.CWD)
	field("model", &in.Model)
	field("workspace", &in.Workspace)
	field("cost", &in.Cost)
	field("version", &in.Version)
	in.OutputStyle = outputStyle(top["output_style"])

	var p payloadProbe
	field("hook_event_name", &p.HookEventName)
	field("session", &p.Session)
	field("model", &p.Model)
	p.SessionID = top["session_id"]
	p.Runtime = top["runtime"]
	for _, row := range payloadShapes {
		if row.match(p) {
			row.normalize(&in, p)
			return in, row.shape, nil
		}
	}
	return in, ShapeClaude, nil
}

// outputStyle reads output_style as either a bare string or Claude Code's
// {"name": ...} object.
func outputStyle(raw json.RawMessage) *string {
	if len(raw) == 0 {
		return nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return &s
	}
	var obj struct {
		Name *string `json:"name"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		return obj.Name
	}
	return nil
}
