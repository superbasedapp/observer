package hook

import (
	"bytes"
	"testing"
)

// The Go 1.27 toolchain backs encoding/json with the v2 implementation
// (plan docs/plans/security-pillar-plan-2026-10-19.md §8.4, risk T17,
// adversarial case X31). The v1 API keeps v1 semantics, but a hook payload
// that suddenly failed to decode would fail CLOSED under enforcement
// (HOOKFAIL-1), so these tests pin, over the real per-client payloads in
// testdata/guard, exactly what the hook decode path produces for the
// shapes the v2 defaults treat differently: unknown fields, field-name
// case, duplicate keys, invalid UTF-8, lone surrogates, null versus
// missing, number handling, a byte-order mark and trailing whitespace.
//
// Every expectation below was taken from the v1 implementation
// (GOEXPERIMENT=nojsonv2, which restores the Go 1.26 decoder) and must hold
// unchanged under the default Go 1.27 build. A failure here means the
// toolchain changed how a vendor payload decodes: make the decode path
// tolerant, never update the expectation to the new behaviour.

// jsonMutation rewrites one real fixture at the byte level (never through
// a decode and re-encode, which would erase the very duplicate keys and
// invalid bytes under test).
type jsonMutation struct {
	name string
	// apply returns the mutated body; t is used to fail when the
	// fixture no longer contains the text the mutation targets.
	apply func(t *testing.T, body []byte) []byte
}

// mustReplace replaces old with new exactly once, failing the test when
// old is absent so a fixture edit cannot silently turn a mutation into a
// no-op.
func mustReplace(t *testing.T, body []byte, old, new string) []byte {
	t.Helper()
	if !bytes.Contains(body, []byte(old)) {
		t.Fatalf("fixture lost %q; the mutation would be a no-op", old)
	}
	return bytes.Replace(body, []byte(old), []byte(new), 1)
}

// afterOpenBrace inserts members right after the payload's opening brace.
func afterOpenBrace(t *testing.T, body []byte, members string) []byte {
	t.Helper()
	i := bytes.IndexByte(body, '{')
	if i < 0 {
		t.Fatalf("fixture is not a JSON object")
	}
	out := append([]byte{}, body[:i+1]...)
	out = append(out, members...)
	return append(out, body[i+1:]...)
}

// beforeCloseBrace appends members before the payload's closing brace.
func beforeCloseBrace(t *testing.T, body []byte, members string) []byte {
	t.Helper()
	i := bytes.LastIndexByte(body, '}')
	if i < 0 {
		t.Fatalf("fixture is not a JSON object")
	}
	out := append([]byte{}, body[:i]...)
	out = append(out, members...)
	return append(out, body[i:]...)
}

// claudeDecoded is the slice of policy.Event the Claude Code decode path
// fills from the payload itself (Now and Caps are not payload data).
type claudeDecoded struct {
	ok         bool
	kind       string
	actionType string
	target     string
	cwd        string
	sessionID  string
}

func decodeClaude(body []byte) claudeDecoded {
	ev, ok := BuildClaudeCodeEvent(body)
	return claudeDecoded{
		ok: ok, kind: string(ev.Kind), actionType: ev.ActionType,
		target: ev.Target, cwd: ev.Cwd, sessionID: ev.SessionID,
	}
}

// TestHookJSONCompat_ClaudeCode pins the Claude Code PreToolUse decode over
// every real claude-code fixture and every mutation.
func TestHookJSONCompat_ClaudeCode(t *testing.T) {
	t.Parallel()
	fixtures := []struct {
		file   string
		target string // the operand the mutations rewrite
		want   claudeDecoded
	}{
		{
			file: "pretool_bash_rmrf.json", target: "rm -rf ~",
			want: claudeDecoded{ok: true, kind: "shell_exec", actionType: "run_command", target: "rm -rf ~", cwd: "/home/dev/proj", sessionID: "fixture-cc-1"},
		},
		{
			file: "pretool_bash_rmrf_wslbridge.json", target: "rm -rf ~",
			want: claudeDecoded{ok: true, kind: "shell_exec", actionType: "run_command", target: "rm -rf ~", cwd: `C:\Users\dev\proj`, sessionID: "fixture-cc-bridge-1"},
		},
		{
			file: "pretool_read_sensitive.json", target: "~/.aws/credentials",
			want: claudeDecoded{ok: true, kind: "file_access", actionType: "read_file", target: "~/.aws/credentials", cwd: "/home/dev/proj", sessionID: "fixture-cc-2"},
		},
	}
	for _, fx := range fixtures {
		fx := fx
		body := loadFixture(t, "claude-code", fx.file)
		failed := claudeDecoded{}
		cases := []struct {
			mutation jsonMutation
			want     func(base claudeDecoded) claudeDecoded
		}{
			{
				jsonMutation{"as-is", func(_ *testing.T, b []byte) []byte { return b }},
				func(b claudeDecoded) claudeDecoded { return b },
			},
			{jsonMutation{"unknown fields of every type are ignored", func(t *testing.T, b []byte) []byte {
				return afterOpenBrace(t, b, `"zz_unknown":{"n":[1,2.5,null,true,"s"],"big":123456789012345678901234567890,"tiny":1e-400,"huge":1e400,"neg":-0},"permission_mode":"default",`)
			}}, func(b claudeDecoded) claudeDecoded { return b }},
			{jsonMutation{"trailing whitespace", func(_ *testing.T, b []byte) []byte {
				return append(append([]byte{}, b...), "\n\r\n\t "...)
			}}, func(b claudeDecoded) claudeDecoded { return b }},
			{jsonMutation{"duplicate key: the last value wins", func(t *testing.T, b []byte) []byte {
				return beforeCloseBrace(t, b, `,"session_id":"dup-last"`)
			}}, func(b claudeDecoded) claudeDecoded { b.sessionID = "dup-last"; return b }},
			{jsonMutation{"duplicate key: an earlier value loses", func(t *testing.T, b []byte) []byte {
				return afterOpenBrace(t, b, `"session_id":"dup-first","cwd":"/decoy",`)
			}}, func(b claudeDecoded) claudeDecoded { return b }},
			{jsonMutation{"duplicate key differing only in case: the last wins", func(t *testing.T, b []byte) []byte {
				return beforeCloseBrace(t, b, `,"SESSION_ID":"dup-case"`)
			}}, func(b claudeDecoded) claudeDecoded { b.sessionID = "dup-case"; return b }},
			{jsonMutation{"field name case is matched case-insensitively", func(t *testing.T, b []byte) []byte {
				b = mustReplace(t, b, `"cwd"`, `"CWD"`)
				return mustReplace(t, b, `"session_id"`, `"Session_Id"`)
			}}, func(b claudeDecoded) claudeDecoded { return b }},
			{jsonMutation{"camelCase is a different name, not a case variant", func(t *testing.T, b []byte) []byte {
				return mustReplace(t, b, `"session_id"`, `"sessionId"`)
			}}, func(b claudeDecoded) claudeDecoded { b.sessionID = ""; return b }},
			{jsonMutation{"invalid UTF-8 in the operand becomes U+FFFD", func(t *testing.T, b []byte) []byte {
				return mustReplace(t, b, `"`+fx.target+`"`, "\""+fx.target+"\xff\xfe\"")
			}}, func(b claudeDecoded) claudeDecoded { b.target += "\uFFFD\uFFFD"; return b }},
			{jsonMutation{"invalid UTF-8 in an unrelated field is harmless", func(t *testing.T, b []byte) []byte {
				return afterOpenBrace(t, b, "\"zz_note\":\"tool output \xc3\x28 bytes\",")
			}}, func(b claudeDecoded) claudeDecoded { return b }},
			{jsonMutation{"invalid UTF-8 in a key", func(t *testing.T, b []byte) []byte {
				return afterOpenBrace(t, b, "\"zz\xffkey\":1,")
			}}, func(b claudeDecoded) claudeDecoded { return b }},
			{jsonMutation{"a lone surrogate escape becomes U+FFFD", func(t *testing.T, b []byte) []byte {
				return mustReplace(t, b, `"`+fx.target+`"`, `"`+fx.target+`\ud800"`)
			}}, func(b claudeDecoded) claudeDecoded { b.target += "\uFFFD"; return b }},
			{jsonMutation{"null leaves the field empty", func(t *testing.T, b []byte) []byte {
				return mustReplace(t, b, `"session_id": "`+fx.want.sessionID+`"`, `"session_id": null`)
			}}, func(b claudeDecoded) claudeDecoded { b.sessionID = ""; return b }},
			{jsonMutation{"a missing field is empty, the same as null", func(t *testing.T, b []byte) []byte {
				return mustReplace(t, b, `"session_id": "`+fx.want.sessionID+`",`, ``)
			}}, func(b claudeDecoded) claudeDecoded { b.sessionID = ""; return b }},
			{jsonMutation{"a null tool_input yields no operand", func(t *testing.T, b []byte) []byte {
				i := bytes.Index(b, []byte(`"tool_input"`))
				if i < 0 {
					t.Fatalf("fixture lost tool_input")
				}
				return append(append([]byte{}, b[:i]...), `"tool_input": null}`...)
			}}, func(claudeDecoded) claudeDecoded { return failed }},
			{jsonMutation{"a number where a string belongs fails the decode", func(t *testing.T, b []byte) []byte {
				return mustReplace(t, b, `"session_id": "`+fx.want.sessionID+`"`, `"session_id": 12345678901234567890`)
			}}, func(claudeDecoded) claudeDecoded { return failed }},
			{jsonMutation{"an earlier numeric tool_name fails the decode even with a valid one later", func(t *testing.T, b []byte) []byte {
				return afterOpenBrace(t, b, `"tool_name":7,`)
			}}, func(claudeDecoded) claudeDecoded { return failed }},
			// FU-161: a leading UTF-8 BOM (a .NET / PowerShell stdin
			// writer's) is stripped, so the payload decodes as itself; it
			// used to read as not JSON and reach the approve-if-unevaluable
			// path unjudged.
			{jsonMutation{"a byte-order mark is stripped", func(_ *testing.T, b []byte) []byte {
				return append([]byte("\xef\xbb\xbf"), b...)
			}}, func(b claudeDecoded) claudeDecoded { return b }},
			{jsonMutation{"a truncated body is not JSON", func(_ *testing.T, b []byte) []byte {
				return b[:len(b)/2]
			}}, func(claudeDecoded) claudeDecoded { return failed }},
			{jsonMutation{"trailing garbage after the object is not JSON", func(_ *testing.T, b []byte) []byte {
				return append(append([]byte{}, b...), " x"...)
			}}, func(claudeDecoded) claudeDecoded { return failed }},
		}
		for _, tc := range cases {
			tc := tc
			t.Run(fx.file+"/"+tc.mutation.name, func(t *testing.T) {
				t.Parallel()
				got := decodeClaude(tc.mutation.apply(t, body))
				if want := tc.want(fx.want); got != want {
					t.Errorf("decoded\n got %+v\nwant %+v", got, want)
				}
			})
		}
	}
}

// TestHookJSONCompat_PayloadFieldString pins the forensic field reader
// every hook reply path uses for its hook-events.jsonl row: it must keep
// reading the same values from the same odd shapes.
func TestHookJSONCompat_PayloadFieldString(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, body, key, want string
	}{
		{"plain", `{"session_id":"s1","tool_name":"Bash"}`, "tool_name", "Bash"},
		{"duplicate key, last wins", `{"tool_name":"A","tool_name":"B"}`, "tool_name", "B"},
		{"invalid UTF-8 becomes U+FFFD", "{\"tool_name\":\"Ba\xffsh\"}", "tool_name", "Ba\uFFFDsh"},
		{"exact key only, no case folding for a map", `{"TOOL_NAME":"Bash"}`, "tool_name", ""},
		{"null", `{"tool_name":null}`, "tool_name", ""},
		{"number is not a string", `{"tool_name":7}`, "tool_name", ""},
		{"not JSON", `{"tool_name":`, "tool_name", ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := payloadFieldString([]byte(tc.body), tc.key); got != tc.want {
				t.Errorf("payloadFieldString(%q) = %q, want %q", tc.key, got, tc.want)
			}
		})
	}
}
