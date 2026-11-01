//go:build !sbo_omit_adapter_cursor

package hook

import (
	"bytes"
	"testing"
)

// cursorDecoded is the slice of policy.Event the Cursor pre-execution
// decode path fills from the payload itself.
type cursorDecoded struct {
	ok          bool
	kind        string
	actionType  string
	target      string
	projectRoot string
	sessionID   string
}

func decodeCursor(body []byte) cursorDecoded {
	ev, ok := BuildCursorEvent("beforeShellExecution", body, nil)
	return cursorDecoded{
		ok: ok, kind: string(ev.Kind), actionType: ev.ActionType,
		target: ev.Target, projectRoot: ev.ProjectRoot, sessionID: ev.SessionID,
	}
}

// TestHookJSONCompat_Cursor is TestHookJSONCompat_ClaudeCode for the
// Cursor beforeShellExecution channel: the same Go 1.27 JSON shapes,
// pinned over the real cursor fixtures (see jsoncompat_test.go).
func TestHookJSONCompat_Cursor(t *testing.T) {
	t.Parallel()
	fixtures := []struct {
		file    string
		command string
		want    cursorDecoded
	}{
		{
			file: "before_shell_rmrf.json", command: "rm -rf ~",
			want: cursorDecoded{ok: true, kind: "shell_exec", actionType: "run_command", target: "rm -rf ~", projectRoot: "/home/dev/proj", sessionID: "fixture-cur-1"},
		},
		{
			file: "before_shell_benign.json", command: "go test ./...",
			want: cursorDecoded{ok: true, kind: "shell_exec", actionType: "run_command", target: "go test ./...", projectRoot: "/home/dev/proj", sessionID: "fixture-cur-2"},
		},
	}
	for _, fx := range fixtures {
		fx := fx
		body := loadFixture(t, "cursor", fx.file)
		failed := cursorDecoded{}
		convKey := `"conversation_id": "` + fx.want.sessionID + `"`
		cases := []struct {
			mutation jsonMutation
			want     func(base cursorDecoded) cursorDecoded
		}{
			{
				jsonMutation{"as-is", func(_ *testing.T, b []byte) []byte { return b }},
				func(b cursorDecoded) cursorDecoded { return b },
			},
			{jsonMutation{"unknown fields of every type are ignored", func(t *testing.T, b []byte) []byte {
				return afterOpenBrace(t, b, `"zz_unknown":{"n":[1,2.5,null,true,"s"],"big":123456789012345678901234567890,"tiny":1e-400,"huge":1e400,"neg":-0},"cursor_version":"3.23.12","sandbox":false,`)
			}}, func(b cursorDecoded) cursorDecoded { return b }},
			{jsonMutation{"duplicate key: the last value wins", func(t *testing.T, b []byte) []byte {
				return beforeCloseBrace(t, b, `,"conversation_id":"dup-last"`)
			}}, func(b cursorDecoded) cursorDecoded { b.sessionID = "dup-last"; return b }},
			{jsonMutation{"duplicate key: an earlier value loses", func(t *testing.T, b []byte) []byte {
				return afterOpenBrace(t, b, `"conversation_id":"dup-first","command":"echo decoy",`)
			}}, func(b cursorDecoded) cursorDecoded { return b }},
			{jsonMutation{"field name case is matched case-insensitively", func(t *testing.T, b []byte) []byte {
				b = mustReplace(t, b, `"command"`, `"COMMAND"`)
				return mustReplace(t, b, `"conversation_id"`, `"Conversation_ID"`)
			}}, func(b cursorDecoded) cursorDecoded { return b }},
			{jsonMutation{"invalid UTF-8 in the command becomes U+FFFD", func(t *testing.T, b []byte) []byte {
				return mustReplace(t, b, `"`+fx.command+`"`, "\""+fx.command+"\xff\"")
			}}, func(b cursorDecoded) cursorDecoded { b.target += "�"; return b }},
			{jsonMutation{"a lone surrogate escape becomes U+FFFD", func(t *testing.T, b []byte) []byte {
				return mustReplace(t, b, `"`+fx.command+`"`, `"`+fx.command+`\udfff"`)
			}}, func(b cursorDecoded) cursorDecoded { b.target += "�"; return b }},
			{jsonMutation{"a null conversation_id refuses the event", func(t *testing.T, b []byte) []byte {
				return mustReplace(t, b, convKey, `"conversation_id": null`)
			}}, func(cursorDecoded) cursorDecoded { return failed }},
			{jsonMutation{"a number where a string belongs fails the decode", func(t *testing.T, b []byte) []byte {
				return mustReplace(t, b, convKey, `"conversation_id": 42`)
			}}, func(cursorDecoded) cursorDecoded { return failed }},
			{jsonMutation{"a byte-order mark is not JSON", func(_ *testing.T, b []byte) []byte {
				return append([]byte("\xef\xbb\xbf"), b...)
			}}, func(cursorDecoded) cursorDecoded { return failed }},
			{jsonMutation{"trailing whitespace", func(_ *testing.T, b []byte) []byte {
				return append(bytes.Clone(b), "\r\n"...)
			}}, func(b cursorDecoded) cursorDecoded { return b }},
		}
		for _, tc := range cases {
			tc := tc
			t.Run(fx.file+"/"+tc.mutation.name, func(t *testing.T) {
				t.Parallel()
				got := decodeCursor(tc.mutation.apply(t, body))
				if want := tc.want(fx.want); got != want {
					t.Errorf("decoded\n got %+v\nwant %+v", got, want)
				}
			})
		}
	}
}
