package kimchi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestPermissionModeStamped pins the `custom:permission_mode` payload
// (live: {"mode":"default","source":"config","initiatedBy":"user"}) onto
// every row the session produces after it, user prompts included.
func TestPermissionModeStamped(t *testing.T) {
	for _, tc := range []struct{ file, id string }{
		{"session-wsl.jsonl", wslSessionID},
		{"session-windows.jsonl", winSessionID},
		{"session-agent-parent-wsl.jsonl", agentParentID},
	} {
		t.Run(tc.file, func(t *testing.T) {
			a, path := fixture(t, tc.file, tc.id)
			res := parse(t, a, path, 0)
			stamped := 0
			for _, e := range res.ToolEvents {
				if e.ActionType == models.ActionSessionStart {
					continue // the header precedes the permission entry
				}
				if e.Metadata == nil || e.Metadata.PermissionMode != "default" {
					t.Fatalf("%s (%s) metadata = %+v, want permission_mode default", e.SourceEventID, e.ActionType, e.Metadata)
				}
				stamped++
			}
			if stamped == 0 {
				t.Fatal("no row carried the permission mode")
			}
		})
	}
}

// TestPermissionModeChangeAndRecovery: a later permission_mode entry wins,
// and a resumed parse recovers the mode from behind the cursor.
func TestPermissionModeChangeAndRecovery(t *testing.T) {
	lines := []string{
		`{"type":"session","version":3,"id":"x","timestamp":"2026-10-21T07:00:00.000Z","cwd":"/nonexistent/p"}`,
		`{"type":"custom","customType":"permission_mode","data":{"mode":"default","source":"config","initiatedBy":"user"},"id":"p1","timestamp":"2026-10-21T07:00:01.000Z"}`,
		`{"type":"message","id":"u1","timestamp":"2026-10-21T07:00:02.000Z","message":{"role":"user","content":[{"type":"text","text":"one"}],"timestamp":1792566002000}}`,
		`{"type":"custom","customType":"multi_model_enabled","data":false,"id":"m1","timestamp":"2026-10-21T07:00:03.000Z"}`,
		`{"type":"custom","customType":"permission_mode","data":{"mode":"plan","source":"user","initiatedBy":"user"},"id":"p2","timestamp":"2026-10-21T07:00:04.000Z"}`,
		`{"type":"message","id":"u2","timestamp":"2026-10-21T07:00:05.000Z","message":{"role":"user","content":[{"type":"text","text":"two"}],"timestamp":1792566005000}}`,
	}
	body := strings.Join(lines, "\n") + "\n"
	a, path := writeSession(t, []byte(body), "01a15f00-0000-7000-8000-000000000001")
	res := parse(t, a, path, 0)
	var modes []string
	for _, e := range res.ToolEvents {
		if e.ActionType == models.ActionUserPrompt {
			modes = append(modes, e.Metadata.PermissionMode)
		}
	}
	if len(modes) != 2 || modes[0] != "default" || modes[1] != "plan" {
		t.Fatalf("modes = %v, want [default plan]", modes)
	}
	// Resume after the second permission entry: the prefix replay restores it.
	cut := int64(len(strings.Join(lines[:5], "\n")) + 1)
	again := parse(t, a, path, cut)
	if len(again.ToolEvents) != 1 || again.ToolEvents[0].Metadata == nil || again.ToolEvents[0].Metadata.PermissionMode != "plan" {
		t.Fatalf("resumed events = %+v", again.ToolEvents)
	}
}

// TestSubagentMetadata: a spawned agent's own file stamps the sub-agent
// marker and the parent session id on its rows.
func TestSubagentMetadata(t *testing.T) {
	a, path := fixture(t, "session-agent-child-wsl.jsonl", agentChildID)
	res := parse(t, a, path, 0)
	seen := 0
	for _, e := range res.ToolEvents {
		if e.ActionType == models.ActionSessionStart {
			continue
		}
		if e.Metadata == nil || !e.Metadata.IsSubagent || e.Metadata.ParentSessionID != agentParentID {
			t.Fatalf("%s metadata = %+v, want sub-agent of %s", e.SourceEventID, e.Metadata, agentParentID)
		}
		seen++
	}
	if seen == 0 {
		t.Fatal("no sub-agent rows")
	}
	// The parent session is NOT a sub-agent, and its spawn row is typed.
	pa, ppath := fixture(t, "session-agent-parent-wsl.jsonl", agentParentID)
	pres := parse(t, pa, ppath, 0)
	spawns := 0
	for _, e := range pres.ToolEvents {
		if e.Metadata != nil && e.Metadata.IsSubagent {
			t.Errorf("parent row %s flagged as sub-agent", e.SourceEventID)
		}
		if e.ActionType == models.ActionSpawnSubagent {
			spawns++
		}
	}
	if spawns != 1 || len(pres.SessionLineages) != 0 {
		t.Errorf("spawn rows = %d lineages = %v", spawns, pres.SessionLineages)
	}
}

// TestEditShapeForLOC pins the exact edit / write argument shapes the
// adapter hands the LOC extractor: native args pass through untouched
// (edits[]{oldText,newText}), nothing is dropped.
func TestEditShapeForLOC(t *testing.T) {
	a, path := fixture(t, "session-wsl.jsonl", wslSessionID)
	res := parse(t, a, path, 0)
	var edit, write *models.ToolEvent
	for i := range res.ToolEvents {
		switch res.ToolEvents[i].ActionType {
		case models.ActionEditFile:
			edit = &res.ToolEvents[i]
		case models.ActionWriteFile:
			write = &res.ToolEvents[i]
		}
	}
	if edit == nil || write == nil {
		t.Fatal("edit / write rows missing")
	}
	var ea struct {
		Path  string `json:"path"`
		Edits []struct {
			OldText string `json:"oldText"`
			NewText string `json:"newText"`
		} `json:"edits"`
	}
	if err := json.Unmarshal([]byte(edit.RawToolInput), &ea); err != nil || ea.Path == "" || len(ea.Edits) != 1 || ea.Edits[0].OldText == "" || ea.Edits[0].NewText == "" {
		t.Errorf("edit RawToolInput = %s (err %v)", edit.RawToolInput, err)
	}
	var wa struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := json.Unmarshal([]byte(write.RawToolInput), &wa); err != nil || wa.Path == "" || wa.Content == "" {
		t.Errorf("write RawToolInput = %s (err %v)", write.RawToolInput, err)
	}
	if edit.ContentBytes == 0 || write.ContentBytes == 0 {
		t.Errorf("content bytes edit=%d write=%d", edit.ContentBytes, write.ContentBytes)
	}
}

// TestInstallVersion stamps every session with the install-level
// `lastChangelogVersion` from the agent dir's settings.json, and only that
// field is ever decoded.
func TestInstallVersion(t *testing.T) {
	a, path := fixture(t, "session-wsl.jsonl", wslSessionID)
	// path = <agent dir>/sessions/--slug--/file.jsonl
	agentDir := filepath.Dir(filepath.Dir(filepath.Dir(path)))
	if res := parse(t, a, path, 0); len(res.SessionToolVersions) != 0 {
		t.Fatalf("no settings.json yet, versions = %v", res.SessionToolVersions)
	}
	settings := `{"quietStartup":true,"lastChangelogVersion":"1.17.0","defaultProvider":"openai-codex"}`
	if err := os.WriteFile(filepath.Join(agentDir, "settings.json"), []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}
	res := parse(t, a, path, 0)
	want := models.SessionToolVersion{SessionID: wslSessionID, Version: "1.17.0"}
	if len(res.SessionToolVersions) != 1 || res.SessionToolVersions[0] != want {
		t.Fatalf("versions = %v, want [%v]", res.SessionToolVersions, want)
	}
	// A resumed parse past the header still stamps (first-wins at the store).
	if again := parse(t, a, path, 100); len(again.SessionToolVersions) != 1 {
		t.Errorf("resumed parse versions = %v", again.SessionToolVersions)
	}
	for _, bad := range []string{`{"lastChangelogVersion":"1.17.0 beta"}`, `{"lastChangelogVersion":""}`, `{not json`} {
		if err := os.WriteFile(filepath.Join(agentDir, "settings.json"), []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if res := parse(t, a, path, 0); len(res.SessionToolVersions) != 0 {
			t.Errorf("settings %q stamped %v", bad, res.SessionToolVersions)
		}
	}
}

func TestReadTranscript(t *testing.T) {
	a, path := fixture(t, "session-wsl.jsonl", wslSessionID)
	sess := models.Session{ID: wslSessionID, Tool: models.ToolKimchi}

	// Hint path and root-walk resolution must agree.
	byHint, err := a.ReadTranscript(context.Background(), sess, []string{path})
	if err != nil {
		t.Fatal(err)
	}
	byWalk, err := a.ReadTranscript(context.Background(), sess, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(byHint) == 0 || len(byHint) != len(byWalk) {
		t.Fatalf("hint %d vs walk %d messages", len(byHint), len(byWalk))
	}

	users, assistants, calls, resolved := 0, 0, 0, 0
	tools := map[string]bool{}
	for i, m := range byHint {
		if m.Index != i {
			t.Errorf("message %d index = %d", i, m.Index)
		}
		switch m.Role {
		case models.TranscriptUser:
			users++
		case models.TranscriptAssistant:
			assistants++
			for _, c := range m.ToolCalls {
				calls++
				tools[c.Name] = true
				if c.Resolved {
					resolved++
				}
			}
		}
	}
	if users != 4 {
		t.Errorf("user messages = %d, want 4", users)
	}
	if assistants == 0 || calls == 0 || resolved != calls {
		t.Errorf("assistants=%d calls=%d resolved=%d (every call has a result)", assistants, calls, resolved)
	}
	for _, name := range []string{"bash", "edit", "write", "read", "mark_todo"} {
		if !tools[name] {
			t.Errorf("tool %q missing from transcript (have %v)", name, tools)
		}
	}
	// Model is the provider-qualified string the parser uses.
	foundModel := false
	for _, m := range byHint {
		if m.Role == models.TranscriptAssistant && m.Model == "openai-codex/gpt-5.6-luna" {
			foundModel = true
		}
	}
	if !foundModel {
		t.Error("no assistant message carried openai-codex/gpt-5.6-luna")
	}

	full, err := a.ReadTranscriptFull(context.Background(), sess, []string{path})
	if err != nil {
		t.Fatal(err)
	}
	if len(full) != len(byHint) {
		t.Errorf("full %d vs capped %d messages", len(full), len(byHint))
	}

	if _, err := a.ReadTranscript(context.Background(), models.Session{ID: "01a15fff-0000-7000-8000-000000000009"}, nil); err == nil {
		t.Error("unknown session must error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.ReadTranscript(ctx, sess, []string{path}); err == nil {
		t.Error("cancelled context must error")
	}
}

// TestReadTranscriptFoldsBashExecution: the operator's `!` shell command is a
// call plus its result in one entry.
func TestReadTranscriptFoldsBashExecution(t *testing.T) {
	body := `{"type":"session","version":3,"id":"x","timestamp":"2026-10-21T07:00:00.000Z","cwd":"/nonexistent/p"}` + "\n" +
		`{"type":"message","id":"b1","timestamp":"2026-10-21T07:00:01.000Z","message":{"role":"bashExecution","command":"ls","output":"a.txt","exitCode":0,"timestamp":1792566001000}}` + "\n"
	a, _ := writeSession(t, []byte(body), "01a15f10-0000-7000-8000-000000000001")
	msgs, err := a.ReadTranscript(context.Background(), models.Session{ID: "01a15f10-0000-7000-8000-000000000001"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || len(msgs[0].ToolCalls) != 1 || msgs[0].ToolCalls[0].Name != "bash" || !msgs[0].ToolCalls[0].Resolved || msgs[0].ToolCalls[0].ResultExcerpt != "a.txt" {
		t.Fatalf("messages = %+v", msgs)
	}
}
