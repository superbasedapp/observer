package scrub

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// Fernet-shaped OpenAI encrypted_content values (urlsafe base64) that each
// carry a substring one of the global secret rows matches. Inside the
// `"encrypted_content":` key the String shield protects them; scrubbed in
// isolation they are corrupted (lane sr-openai-n2).
var encryptedContentHits = []struct {
	name string
	tok  string
}{
	{"api_key_prefixed", "gAAAAABpQx7Rk3Lw-ak-Zq9VvYb2aXc1Yt0uTsR8pQoNmLkJiHgFeDcBa_ZyXwVuTsRqPoNm=="},
	{"github_pat", "gAAAAABpQx7Rghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaZyXwVuTsRqPoNm=="},
	{"aws_access_key", "gAAAAABpQx7RAKIAABCDEFGHIJKLMNOPZyXwVuTsRqPoNm=="},
	{"gcp_api_key", "gAAAAABpQx7RAIzaSyA0123456789abcdefghijklmnopqrstuvZyXwVuTsRqPoNm=="},
}

// fallbackTriggers are realistic tool-output endings that make String's
// greedy `\S+` / `[^"]*` rows run across a closing quote of compact JSON,
// which is what sends ScrubForward to its value-by-value pass.
var fallbackTriggers = []struct {
	name, output, leak string
}{
	{"env export at end of output", "export GITHUB_TOKEN=abcdef0123456789", "abcdef0123456789"},
	{"password colon at end of output", "db password: hunter2longvalue", "hunter2longvalue"},
	{"api_key assignment at end of output", "OPENAI_API_KEY=sentinel-value-0123", "sentinel-value-0123"},
}

func responsesBody(output, tok string) string {
	return `{"model":"gpt-5.1-codex-mini","store":false,"include":["reasoning.encrypted_content"],"input":[` +
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"check the env"}]},` +
		`{"type":"reasoning","id":"rs_1","summary":[],"encrypted_content":"` + tok + `"},` +
		`{"type":"function_call","name":"exec_command","arguments":"{\"cmd\":\"env\"}","call_id":"call_1"},` +
		`{"type":"function_call_output","call_id":"call_1","output":"` + output + `"},` +
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"thanks, now continue please"}]}]}`
}

type responsesItems struct {
	Input []map[string]any `json:"input"`
}

// TestScrubForwardKeepsEncryptedContentOnFallback is the sr-openai-n2
// regression: when another string in the body forces ScrubForward off its
// fast path, the encrypted_content value must still reach the upstream
// byte-identical (it used to come back as `…-[REDACTED:api_key_prefixed]==`
// and every follow-up turn failed with "encrypted content could not be
// verified").
func TestScrubForwardKeepsEncryptedContentOnFallback(t *testing.T) {
	t.Parallel()
	for _, hit := range encryptedContentHits {
		for _, trig := range fallbackTriggers {
			t.Run(hit.name+"/"+trig.name, func(t *testing.T) {
				body := responsesBody(trig.output, hit.tok)
				for name, scrub := range map[string]func([]byte) []byte{
					"ScrubForward":         New().ScrubForward,
					"ScrubProviderRequest": New().ScrubProviderRequest,
				} {
					out := scrub([]byte(body))
					if !json.Valid(out) {
						t.Fatalf("%s: invalid JSON: %s", name, out)
					}
					if !bytes.Contains(out, []byte(`"encrypted_content":"`+hit.tok+`"`)) {
						t.Fatalf("%s: encrypted_content not byte-exact:\n%s", name, out)
					}
					if bytes.Contains(out, []byte(trig.leak)) {
						t.Fatalf("%s: trigger secret %q not redacted:\n%s", name, trig.leak, out)
					}
					var v responsesItems
					if err := json.Unmarshal(out, &v); err != nil || len(v.Input) != 5 {
						t.Fatalf("%s: want 5 input items, got %d (%v):\n%s", name, len(v.Input), err, out)
					}
				}
			})
		}
	}
}

// TestScrubForwardNeverDeletesItems pins the second half of the defect: a
// greedy row could swallow whole items and still leave VALID JSON, which the
// old "still valid" check forwarded (the reasoning item and the user's next
// message vanished). The structure check refuses that output.
func TestScrubForwardNeverDeletesItems(t *testing.T) {
	t.Parallel()
	body := `{"input":[{"type":"function_call_output","call_id":"c1","output":"token: x"},` +
		`{"type":"reasoning","id":"rs_1","encrypted_content":"gAAAAABtok=="},` +
		`{"type":"message","role":"user","content":"hello world"}]}`
	for _, scrub := range []func([]byte) []byte{New().ScrubForward, New().ScrubProviderRequest} {
		out := scrub([]byte(body))
		var v responsesItems
		if err := json.Unmarshal(out, &v); err != nil {
			t.Fatalf("invalid JSON: %v\n%s", err, out)
		}
		if len(v.Input) != 3 {
			t.Fatalf("items = %d, want 3 (structure deleted):\n%s", len(v.Input), out)
		}
		if v.Input[1]["encrypted_content"] != "gAAAAABtok==" || v.Input[2]["content"] != "hello world" {
			t.Fatalf("items altered:\n%s", out)
		}
		if strings.Contains(string(out), `"token: x"`) {
			t.Fatalf("token value not redacted:\n%s", out)
		}
	}
}

// TestVerifiedPositionsHaveTestRows: every protocol position in
// verifiedPositions has a realistic body in anchoredCases
// (forward_anchor_test.go) that exercises it on both scrub paths, and
// every field of the row is actually kept by that body.
func TestVerifiedPositionsHaveTestRows(t *testing.T) {
	t.Parallel()
	covered := map[string]bool{}
	for _, tc := range anchoredCases {
		covered[tc.position] = true
	}
	for _, p := range verifiedPositions {
		if !covered[p.name] {
			t.Errorf("verifiedPositions row %q has no anchoredCases row", p.name)
		}
		if len(p.path) == 0 || len(p.fields) == 0 || p.why == "" {
			t.Errorf("verifiedPositions row %q is incomplete", p.name)
		}
	}
	for _, tc := range anchoredCases {
		toks := walkJSON([]byte(tc.body))
		kept := map[string]bool{}
		for _, tk := range toks {
			if tk.keepVerified {
				kept[tk.member] = true
			}
		}
		for _, p := range verifiedPositions {
			if p.name != tc.position {
				continue
			}
			for _, f := range p.fields {
				if !kept[f.member] {
					t.Errorf("%s: field %q (type %q) is not kept by its test body", p.name, f.member, f.objType)
				}
			}
		}
	}
}

// TestScrubProviderRequestCleanAndIdempotent pins byte stability: a clean
// body comes back as the same slice contents, and a second pass over a
// scrubbed body changes nothing.
func TestScrubProviderRequestCleanAndIdempotent(t *testing.T) {
	t.Parallel()
	clean := []byte(responsesBody("ok", encryptedContentHits[0].tok))
	if out := New().ScrubProviderRequest(clean); !bytes.Equal(out, clean) {
		t.Fatalf("clean body mutated:\n got %s\nwant %s", out, clean)
	}
	dirty := []byte(responsesBody(fallbackTriggers[0].output, encryptedContentHits[0].tok))
	once := New().ScrubProviderRequest(dirty)
	if twice := New().ScrubProviderRequest(once); !bytes.Equal(once, twice) {
		t.Fatalf("not idempotent:\n%s\n%s", once, twice)
	}
}

// TestSpliceScrubPreservesUntouchedBytes: the value-by-value pass rewrites
// only the changed values, so pretty-printing, key order, unicode escapes
// and HTML characters elsewhere survive exactly.
func TestSpliceScrubPreservesUntouchedBytes(t *testing.T) {
	t.Parallel()
	in := "{\n  \"z\": \"caf\\u00e9 <b> & co\",\n  \"a\": [1, 2.5e3, true, null, {\"k\\\"q\": \"x\"}],\n  \"s\": \"password: hunter2longvalue\"\n}"
	out := New().spliceScrub([]byte(in), false)
	want := strings.Replace(in, "password: hunter2longvalue", "password: [REDACTED]", 1)
	if string(out) != want {
		t.Fatalf("splice changed untouched bytes:\n got %s\nwant %s", out, want)
	}
	if same := New().spliceScrub([]byte(want), false); !bytes.Equal(same, []byte(want)) {
		t.Fatalf("clean splice not identity: %s", same)
	}
}

// TestWalkJSONTokens pins the walker's key / value / parentKey / member /
// kept classification on a document with escapes, nested arrays, a
// thinking block at its protocol position and a look-alike one nested in
// tool output.
func TestWalkJSONTokens(t *testing.T) {
	t.Parallel()
	doc := `{"a":["x",{"b":"y"}],"k\"e":"v","encrypted_content":["e"],"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"t","signature":"s","note":"n"},` +
		`{"type":"tool_use","input":{"type":"thinking","thinking":"u"}}]}],"encrypted_content":"f","n":-1.5e2}`
	toks := walkJSON([]byte(doc))
	type got struct {
		text, parent, member string
		kind                 byte
		always, verified     bool
	}
	var strs []got
	for _, tk := range toks {
		if tk.kind == tokStr || tk.kind == tokKey || tk.kind == tokLit {
			strs = append(strs, got{doc[tk.start:tk.end], tk.parentKey, tk.member, tk.kind, tk.keepAlways, tk.keepVerified})
		}
	}
	want := []got{
		{`"a"`, "", "a", tokKey, false, false},
		{`"x"`, "a", "", tokStr, false, false},
		{`"b"`, "", "b", tokKey, false, false},
		{`"y"`, "b", "b", tokStr, false, false},
		{`"k\"e"`, "", `k\"e`, tokKey, false, false},
		{`"v"`, `k"e`, `k\"e`, tokStr, false, false},
		{`"encrypted_content"`, "", "encrypted_content", tokKey, false, false},
		{`"e"`, "encrypted_content", "", tokStr, false, false}, // array element: not a direct member
		{`"messages"`, "", "messages", tokKey, false, false},
		{`"role"`, "", "role", tokKey, false, false},
		{`"assistant"`, "role", "role", tokStr, false, false},
		{`"content"`, "", "content", tokKey, false, false},
		{`"type"`, "", "type", tokKey, false, false},
		{`"thinking"`, "type", "type", tokStr, false, false},
		{`"thinking"`, "", "thinking", tokKey, false, false},
		{`"t"`, "thinking", "thinking", tokStr, false, true},
		{`"signature"`, "", "signature", tokKey, false, false},
		{`"s"`, "signature", "signature", tokStr, false, true},
		{`"note"`, "", "note", tokKey, false, false},
		{`"n"`, "note", "note", tokStr, false, false}, // sibling: not kept
		{`"type"`, "", "type", tokKey, false, false},
		{`"tool_use"`, "type", "type", tokStr, false, false},
		{`"input"`, "", "input", tokKey, false, false},
		{`"type"`, "", "type", tokKey, false, false},
		{`"thinking"`, "type", "type", tokStr, false, false},
		{`"thinking"`, "", "thinking", tokKey, false, false},
		{`"u"`, "thinking", "thinking", tokStr, false, false}, // look-alike in tool_use.input
		{`"encrypted_content"`, "", "encrypted_content", tokKey, false, false},
		{`"f"`, "encrypted_content", "encrypted_content", tokStr, true, false},
		{`"n"`, "", "n", tokKey, false, false},
		{`-1.5e2`, "", "", tokLit, false, false},
	}
	if len(strs) != len(want) {
		t.Fatalf("tokens = %d, want %d: %+v", len(strs), len(want), strs)
	}
	for i := range want {
		if strs[i] != want[i] {
			t.Errorf("token %d = %+v, want %+v", i, strs[i], want[i])
		}
	}
}

// FuzzScrubForwardKeepsShape: for any valid JSON, both forward scrubs
// return valid JSON with the input's exact token structure (delimiters and
// literals byte-identical, kept member names and kept values untouched).
func FuzzScrubForwardKeepsShape(f *testing.F) {
	f.Add([]byte(responsesBody(fallbackTriggers[0].output, encryptedContentHits[0].tok)))
	f.Add([]byte(`{"input":[{"output":"token: x"},{"type":"reasoning","encrypted_content":"a-ak-bbbbbbbbbbbbbbbbbbbb"},{"c":"hello world"}]}`))
	f.Add([]byte(`["password=abc def", {"api_key": "sk-0123456789abcdefgh"}, 1, null, "://u:p@h"]`))
	f.Add([]byte(`{"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"secret: x","signature":"AKIA` + `ABCDEFGHIJKLMNOP"}]}]}`))
	f.Add([]byte(`{"metadata":{"ghp_abcdefghijklmnopqrstuvwxyz0123":"1","password":"x y"}}`))
	f.Add([]byte(`"Bearer abcdefghijklmnop"`))
	for _, tc := range anchoredCases {
		f.Add([]byte(tc.body))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		if !json.Valid(in) {
			return
		}
		for _, protect := range []bool{false, true} {
			out := New().scrubForward(in, protect)
			if !json.Valid(out) {
				t.Fatalf("invalid JSON out (protect=%v):\n in: %q\nout: %q", protect, in, out)
			}
			a, b := walkJSON(in), walkJSON(out)
			if len(a) != len(b) {
				t.Fatalf("token count %d -> %d (protect=%v):\n in: %q\nout: %q", len(a), len(b), protect, in, out)
			}
			for i := range a {
				if a[i].kind != b[i].kind {
					t.Fatalf("token %d kind changed", i)
				}
				fixed := a[i].kind == tokDelim || a[i].kind == tokLit ||
					(a[i].kind == tokKey && keepsKey(a[i])) ||
					(a[i].kind == tokStr && keepsValue(a[i], protect))
				if fixed && !bytes.Equal(in[a[i].start:a[i].end], out[b[i].start:b[i].end]) {
					t.Fatalf("kept token %d changed (protect=%v): %q -> %q", i, protect, in[a[i].start:a[i].end], out[b[i].start:b[i].end])
				}
			}
		}
	})
}
