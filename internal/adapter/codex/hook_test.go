package codex

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

func TestBuildHookEvent_SessionStart(t *testing.T) {
	body := []byte(`{
	  "session_id":"019e0c21",
	  "transcript_path":"/tmp/codex/2026/05/09/rollout.jsonl",
	  "cwd":"/tmp/ab-codex/on",
	  "hook_event_name":"SessionStart",
	  "model":"gpt-5.5",
	  "permission_mode":"default",
	  "source":"startup"
	}`)
	ev, ok, err := BuildHookEvent("SessionStart", body, scrub.New())
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if ev.SessionID != "019e0c21" {
		t.Errorf("SessionID=%q", ev.SessionID)
	}
	if ev.Tool != models.ToolCodex {
		t.Errorf("Tool=%q", ev.Tool)
	}
	if ev.ActionType != models.ActionSessionStart {
		t.Errorf("ActionType=%q", ev.ActionType)
	}
	if ev.Target != "startup" {
		t.Errorf("Target=%q (want startup)", ev.Target)
	}
	if ev.Model != "gpt-5.5" {
		t.Errorf("Model=%q", ev.Model)
	}
	if ev.SourceFile != "codex:hook" {
		t.Errorf("SourceFile=%q", ev.SourceFile)
	}
}

func TestBuildHookEvent_UserPromptSubmit(t *testing.T) {
	body := []byte(`{
	  "session_id":"019e0c21",
	  "turn_id":"turn-7",
	  "transcript_path":"/tmp/codex/rollout.jsonl",
	  "cwd":"/tmp/ab-codex/on",
	  "hook_event_name":"UserPromptSubmit",
	  "model":"gpt-5.5",
	  "permission_mode":"default",
	  "prompt":"What does this project do?"
	}`)
	ev, ok, err := BuildHookEvent("UserPromptSubmit", body, scrub.New())
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if ev.ActionType != models.ActionUserPrompt {
		t.Errorf("ActionType=%q", ev.ActionType)
	}
	if ev.RawToolInput != "What does this project do?" {
		t.Errorf("RawToolInput=%q", ev.RawToolInput)
	}
	if ev.Target != "What does this project do?" {
		t.Errorf("Target=%q", ev.Target)
	}
	if ev.MessageID != "user:turn-7" {
		t.Errorf("MessageID=%q (want user-scoped turn id)", ev.MessageID)
	}
}

func TestBuildHookEvent_PreAndPostToolUseEmitNoRow(t *testing.T) {
	cases := []string{"PreToolUse", "PostToolUse"}
	for _, ev := range cases {
		body := []byte(`{
		  "session_id":"019e0c21","cwd":"/tmp","hook_event_name":"` + ev + `",
		  "model":"gpt-5.5","tool_name":"Bash","tool_input":{},"tool_use_id":"call_1"
		}`)
		_, ok, err := BuildHookEvent(ev, body, scrub.New())
		if err != nil {
			t.Fatalf("%s err=%v", ev, err)
		}
		if ok {
			t.Errorf("%s: expected no row (codex JSONL/proxy already captures the tool fire)", ev)
		}
	}
}

func TestBuildHookEvent_PermissionRequest(t *testing.T) {
	body := []byte(`{
	  "session_id":"019e0c21","cwd":"/tmp","hook_event_name":"PermissionRequest",
	  "model":"gpt-5.5","tool_name":"Bash",
	  "tool_input":{"command":"rm -rf /"}
	}`)
	ev, ok, err := BuildHookEvent("PermissionRequest", body, scrub.New())
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if ev.RawToolName != "Bash" {
		t.Errorf("RawToolName=%q", ev.RawToolName)
	}
	if !strings.Contains(ev.Target, "Bash") {
		t.Errorf("Target=%q (want contains tool name)", ev.Target)
	}
	if !strings.Contains(ev.RawToolInput, "command") {
		t.Errorf("RawToolInput=%q (want JSON-stringified input)", ev.RawToolInput)
	}
}

// TestBuildHookEvent_PermissionRequest_ScrubsJSONWithoutCorruption pins
// MHC-4 (docs/audits/codebase-audit-2026-09-16.md): tool_input scrubbing
// must go through scrubJSON (scrub.Scrubber.RawJSON), not scrubText
// (scrub.Scrubber.String) — String's line-oriented secret patterns are
// greedy across compact JSON's lack of whitespace and can truncate the
// structure instead of just redacting the matched value.
func TestBuildHookEvent_PermissionRequest_ScrubsJSONWithoutCorruption(t *testing.T) {
	const secret = "sk_live_abcdef1234567890"
	const sibling = "echo hi"
	body := []byte(`{"session_id":"019e0c21","cwd":"/tmp","hook_event_name":"PermissionRequest","model":"gpt-5.5","tool_name":"Bash","tool_input":{"api_key":"` + secret + `","command":"` + sibling + `"}}`)
	ev, ok, err := BuildHookEvent("PermissionRequest", body, scrub.New())
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if !json.Valid([]byte(ev.RawToolInput)) {
		t.Fatalf("RawToolInput is not valid JSON after scrubbing: %q", ev.RawToolInput)
	}
	if strings.Contains(ev.RawToolInput, secret) {
		t.Errorf("secret survived scrubbing: %q", ev.RawToolInput)
	}
	if !strings.Contains(ev.RawToolInput, sibling) {
		t.Errorf("sibling field lost — scrubbing truncated/corrupted the JSON: %q", ev.RawToolInput)
	}
}

func TestBuildHookEvent_StopEmitsNoRow(t *testing.T) {
	body := []byte(`{
	  "session_id":"019e0c21","cwd":"/tmp","hook_event_name":"Stop",
	  "model":"gpt-5.5","stop_hook_active":false,"last_assistant_message":"done"
	}`)
	_, ok, err := BuildHookEvent("Stop", body, scrub.New())
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if ok {
		t.Errorf("Stop: expected no row (proxy/JSONL already capture token data)")
	}
}

func TestBuildHookEvent_RejectsMissingSessionID(t *testing.T) {
	body := []byte(`{"hook_event_name":"SessionStart","cwd":"/tmp"}`)
	if _, _, err := BuildHookEvent("SessionStart", body, scrub.New()); err == nil {
		t.Errorf("expected error for missing session_id")
	}
}

func TestBuildHookEvent_RejectsBadJSON(t *testing.T) {
	if _, _, err := BuildHookEvent("SessionStart", []byte("not json"), scrub.New()); err == nil {
		t.Errorf("expected parse error")
	}
}

// TestBuildHookEvent_PopulatesMetadata pins migration 017 on the
// codex hook adapter: every non-empty event branch carries the
// envelope metadata (permission_mode) on the returned ToolEvent.
// Pre-migration-017, PermissionMode was parsed but never assigned
// (handover note "PermissionMode is parsed but never used").
//
// Effort capture is the JSONL adapter's job (see
// internal/adapter/codex/adapter.go's withEffort wrapper).
// Pre-2026-05-11 this struct also defensively parsed two
// speculative effort shapes (effort.level + collaboration_mode.
// settings.reasoning_effort); both were dropped after the
// capture-first procedure (docs/codex-hook-capture.md) verified
// codex hooks never carry effort.
func TestBuildHookEvent_PopulatesMetadata(t *testing.T) {
	cases := []struct {
		name     string
		event    string
		body     []byte
		wantPerm string
	}{
		{
			name:     "session_start_with_permission_mode",
			event:    "SessionStart",
			body:     []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"SessionStart","permission_mode":"plan","source":"startup"}`),
			wantPerm: "plan",
		},
		{
			name:     "user_prompt_with_permission_mode",
			event:    "UserPromptSubmit",
			body:     []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"UserPromptSubmit","permission_mode":"default","prompt":"hello"}`),
			wantPerm: "default",
		},
		{
			name:     "permission_request_carries_mode",
			event:    "PermissionRequest",
			body:     []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"PermissionRequest","permission_mode":"bypass_permissions","tool_name":"Bash","tool_input":{}}`),
			wantPerm: "bypass_permissions",
		},
		{
			name:     "session_start_no_metadata_keeps_nil",
			event:    "SessionStart",
			body:     []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"SessionStart","source":"startup"}`),
			wantPerm: "",
		},
		{
			// Confirms the dead effort.level path is truly dead —
			// even if a payload includes it, observer no longer
			// extracts it (effort is JSONL-only).
			name:     "stray_effort_level_ignored",
			event:    "SessionStart",
			body:     []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"SessionStart","effort":{"level":"high"}}`),
			wantPerm: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev, ok, err := BuildHookEvent(c.event, c.body, scrub.New())
			if err != nil || !ok {
				t.Fatalf("ok=%v err=%v", ok, err)
			}
			if c.wantPerm == "" {
				if ev.Metadata != nil {
					t.Errorf("Metadata=%+v; want nil for envelope without permission_mode", ev.Metadata)
				}
				return
			}
			if ev.Metadata == nil {
				t.Fatalf("Metadata=nil; want PermissionMode=%q", c.wantPerm)
			}
			if ev.Metadata.PermissionMode != c.wantPerm {
				t.Errorf("PermissionMode=%q want %q", ev.Metadata.PermissionMode, c.wantPerm)
			}
			if ev.Metadata.EffortLevel != "" {
				t.Errorf("EffortLevel=%q; codex hooks never carry effort — extraction should be empty", ev.Metadata.EffortLevel)
			}
		})
	}
}

func TestBuildHookEvent_UnknownEventCapturedAsUnknown(t *testing.T) {
	// Future codex events we haven't seen yet should still surface as
	// rows (ActionUnknown) so dashboards reveal them rather than
	// silently dropping the data.
	body := []byte(`{"hook_event_name":"FutureEvent","session_id":"s1","cwd":"/tmp"}`)
	ev, ok, err := BuildHookEvent("FutureEvent", body, scrub.New())
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if ev.ActionType != models.ActionUnknown {
		t.Errorf("ActionType=%q (want ActionUnknown)", ev.ActionType)
	}
	if !strings.Contains(ev.Target, "FutureEvent") {
		t.Errorf("Target=%q", ev.Target)
	}
}
