package kirocrew

// Pins for the independent-review fixes (H1 / M2 / M4 / L2), each one
// grounded on the same live capture the rest of the package uses.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestResolveOwnership_BlankSIDIsUnresolved is the H1 pin. A map entry
// that EXISTS with a blank `sid` is the Gateway having reserved the slot
// before minting the agent session. Treating that as "no twin" emits the
// whole conversation now and lets kiro-cli emit it again once the sid
// lands — the unrecoverable duplicate direction.
func TestResolveOwnership_BlankSIDIsUnresolved(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want ownership
	}{
		{"blank sid", `{"dashboard:chat-2-1700000002":{"sid":""}}`, ownershipUnresolved},
		{"whitespace sid", `{"dashboard:chat-2-1700000002":{"sid":"   "}}`, ownershipUnresolved},
		{"sid key absent", `{"dashboard:chat-2-1700000002":{"provider":"acp"}}`, ownershipUnresolved},
		{"real sid", `{"dashboard:chat-2-1700000002":{"sid":"s-1"}}`, ownedByKiroCLI},
		{"different slot only", `{"dashboard:chat-9-1700000009":{"sid":"s-1"}}`, ownedBySelf},
		{"malformed json", `{not json`, ownershipUnresolved},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, sessionsDir)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, sessionMapFile), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(dir, fixtureSlot+".jsonl")
			if err := os.WriteFile(p, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if got, _ := resolveOwnership(p); got != tc.want {
				t.Errorf("resolveOwnership = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestToolOutcome is the M2 pin. Crew's `execute` lines carry the SAME
// {exit_status,stdout,stderr} envelope kiro-cli does — but only
// sometimes, so both shapes must work, and a non-zero exit must fail the
// action even though Crew's own `done` flag says the call completed.
func TestToolOutcome(t *testing.T) {
	for _, tc := range []struct {
		name        string
		output      string
		wantOut     string
		wantSuccess bool
		wantErr     bool
	}{
		{"envelope, exit 0", `{"exit_status":"exit code: 0","stdout":"Hello\n","stderr":""}`, "Hello\n", true, false},
		{"envelope, exit 1 with stderr", `{"exit_status":"exit code: 1","stdout":"","stderr":"boom\n"}`, "boom\n", false, true},
		{"envelope, stdout+stderr both", `{"exit_status":"exit code: 1","stdout":"out","stderr":"err"}`, "outerr", false, true},
		{"raw stdout string", "Hello World\n", "Hello World\n", true, false},
		{"raw directory listing", ".kiro\nREADME.md\n", ".kiro\nREADME.md\n", true, false},
		{"raw file-tool message", "Successfully created x.py (1 lines).", "Successfully created x.py (1 lines).", true, false},
		{"empty", "", "", true, false},
		{"json object without exit_status", `{"a":1}`, `{"a":1}`, true, false},
		{"a bare JSON string", `"just text"`, `"just text"`, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, success, errMsg := toolOutcome(toolRecord{output: tc.output})
			if out != tc.wantOut {
				t.Errorf("out = %q, want %q", out, tc.wantOut)
			}
			if success != tc.wantSuccess {
				t.Errorf("success = %v, want %v", success, tc.wantSuccess)
			}
			if (errMsg != "") != tc.wantErr {
				t.Errorf("errMsg = %q, wantErr %v", errMsg, tc.wantErr)
			}
		})
	}
}

// TestEmit_ShellFailuresAreFailures runs the M2 rule over the real
// fixture: the two PowerShell commands that came back `exit code: 1`
// must land as FAILED actions carrying the exit status, and their
// ToolOutput must be the command's own stderr, not the JSON envelope.
func TestEmit_ShellFailuresAreFailures(t *testing.T) {
	root := testdataDir(t, filepath.Join("crew-no-twin", "sessions"))
	res, err := NewWithOptions(nil, root).ParseSessionFile(
		context.Background(), filepath.Join(root, fixtureSlot+".jsonl"), 0)
	if err != nil {
		t.Fatal(err)
	}
	var failed, envelopes int
	for _, e := range res.ToolEvents {
		if e.RawToolName == "" {
			continue
		}
		if strings.Contains(e.ToolOutput, `"exit_status"`) {
			envelopes++
		}
		if !e.Success {
			failed++
			if !strings.Contains(e.ErrorMessage, "exit code: 1") {
				t.Errorf("failed tool %s carries error %q, want the exit status", e.SourceEventID, e.ErrorMessage)
			}
		}
	}
	if failed != 2 {
		t.Errorf("failed tool actions = %d, want 2 (the two non-zero PowerShell exits)", failed)
	}
	if envelopes != 0 {
		t.Errorf("%d tool rows carry the raw JSON envelope as ToolOutput; stdout+stderr must be rendered instead", envelopes)
	}
}

// TestParseConversation_LeadingBlankLine is the M4 pin: a leading blank
// line must not shift the metadata header into the turn-line branch,
// which would silently lose the project root, title and model.
func TestParseConversation_LeadingBlankLine(t *testing.T) {
	body, err := os.ReadFile(testdataDir(t, filepath.Join("crew", "sessions", fixtureSlot+".jsonl")))
	if err != nil {
		t.Fatal(err)
	}
	base := parseConversation(body)
	withBlank := parseConversation(append([]byte("\n\r\n"), body...))

	if withBlank.meta.Title != base.meta.Title || withBlank.meta.Project != base.meta.Project {
		t.Errorf("header lost to a leading blank line: title %q project %q",
			withBlank.meta.Title, withBlank.meta.Project)
	}
	if len(withBlank.events) != len(base.events) {
		t.Errorf("events = %d, want %d", len(withBlank.events), len(base.events))
	}
	if len(withBlank.warnings) != 0 {
		t.Errorf("warnings = %v, want none", withBlank.warnings)
	}
}

// TestEmit_WarnsOnBlankToolKind is the L2 pin: a tool call whose merged
// kind is EMPTY (only a completion half ever landed) is as unmapped as
// an unknown vocabulary token, and must warn rather than pass silently.
func TestEmit_WarnsOnBlankToolKind(t *testing.T) {
	root := filepath.Join(t.TempDir(), sessionsDir)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	// session_map present but not resolving this slot => ownedBySelf.
	if err := os.WriteFile(filepath.Join(filepath.Dir(root), sessionMapFile), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	body := `{"_type":"metadata","title":"t","project":"","model":""}
{"role":"user","content":"hi","meta":{"mid":"m-1"}}
{"role":"tool","content":"done","meta":{"tool_call_id":"tooluse_x","kind":"","done":true}}
`
	p := filepath.Join(root, fixtureSlot+".jsonl")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := NewWithOptions(nil, root).ParseSessionFile(context.Background(), p, 0)
	if err != nil {
		t.Fatal(err)
	}
	var warned bool
	for _, w := range res.Warnings {
		if strings.Contains(w, "tooluse_x") && strings.Contains(w, "unmapped kind") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("warnings = %v, want one naming the blank-kind tool call", res.Warnings)
	}
}
