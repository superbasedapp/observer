package scrub

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// forward_anchor_test.go pins the review findings on lane sr-openai-n2's
// forward scrub (fixup/n2-scrub, 2026-11-23): the exemptions must be no
// wider than the scrub they replaced.
//
//   - A secret in a JSON KEY is scrubbed (String did it on main; the splice
//     pass skipped every key).
//   - encrypted_content is kept only as a DIRECT string member under the
//     LITERAL key name (not array-valued, not under an escaped key).
//   - Provider-verified fields are kept only at their protocol position,
//     and only the opaque field itself, never a sibling or a descendant: a
//     look-alike object inside tool output is scrubbed like anything else.

const (
	anchorGHP = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	anchorSK  = "sk-proj-abcdefghijklmnopqrstuv0123"
	anchorPW  = "hunter2longvalue"
	// escapedEncryptedContentKey is the member name "encrypted_content" spelled
	// with a JSON escape for the underscore: a JSON parser reads it as
	// encrypted_content, but it is not the literal name String shields.
	escapedEncryptedContentKey = `"encrypted\u005fcontent"`
)

// forwardScrubs is both forward-path entry points.
var forwardScrubs = []struct {
	name string
	fn   func([]byte) []byte
}{
	{"ScrubForward", func(b []byte) []byte { return New().ScrubForward(b) }},
	{"ScrubProviderRequest", func(b []byte) []byte { return New().ScrubProviderRequest(b) }},
}

// withFallbackTrigger adds a member whose value ends in a key=value secret
// shape, so String's greedy `\S+` row runs across the closing quote and the
// body takes the value-by-value pass instead of String's own output.
func withFallbackTrigger(body string) string {
	return strings.TrimSuffix(body, "}") + `,"zz_note":"export GITHUB_TOKEN=abcdef0123456789"}`
}

// scrubPaths runs body as written (String's output accepted when the JSON
// shape is unchanged) and with a fallback trigger (the splice pass).
func scrubPaths(body string) []struct{ name, body string } {
	return []struct{ name, body string }{
		{"fast", body},
		{"fallback", withFallbackTrigger(body)},
	}
}

// tokenCount is the number of JSON tokens, the shape a forward scrub must
// keep.
func tokenCount(t *testing.T, b []byte) int {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))
	n := 0
	for {
		if _, err := dec.Token(); err != nil {
			return n
		}
		n++
	}
}

func assertScrubbed(t *testing.T, name string, in, out []byte, leaks []string) {
	t.Helper()
	if !json.Valid(out) {
		t.Fatalf("%s: invalid JSON:\n%s", name, out)
	}
	if a, b := tokenCount(t, in), tokenCount(t, out); a != b {
		t.Fatalf("%s: token count %d -> %d (structure changed):\n%s", name, a, b, out)
	}
	for _, leak := range leaks {
		if bytes.Contains(out, []byte(leak)) {
			t.Errorf("%s: %q reached the forwarded body:\n%s", name, leak, out)
		}
	}
}

// TestForwardScrubRedactsSecretsInKeys: a secret used as an object member
// NAME must not be forwarded. On main String redacted it and the result was
// valid JSON; the splice pass skipped every key, so the shape check sent the
// body there and the key went out raw.
func TestForwardScrubRedactsSecretsInKeys(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, body string
	}{
		{"top-level key", `{"` + anchorGHP + `":"1","model":"m"}`},
		{"nested metadata key", `{"model":"m","metadata":{"` + anchorGHP + `":"1"}}`},
		{"gemini functionResponse.response keyed by a token", `{"contents":[{"role":"model","parts":[{"functionCall":{"name":"read_env","args":{}}}]},` +
			`{"role":"user","parts":[{"functionResponse":{"name":"read_env","response":{"` + anchorSK + `":"present"}}}]}]}`},
		{"key inside an array of objects", `{"input":[{"type":"function_call_output","call_id":"c1","output":[{"` + anchorGHP + `":true}]}]}`},
	}
	for _, tc := range cases {
		for _, p := range scrubPaths(tc.body) {
			for _, s := range forwardScrubs {
				t.Run(tc.name+"/"+p.name+"/"+s.name, func(t *testing.T) {
					in := []byte(p.body)
					assertScrubbed(t, s.name, in, s.fn(in), []string{anchorGHP, anchorSK})
				})
			}
		}
	}
}

// TestForwardScrubKeepsEncryptedContentOnlyAsDirectLiteralMember: the
// encrypted_content exemption covers exactly what String's own shield
// covers, a string that is the DIRECT value of a member named literally
// "encrypted_content". An array under that key, or a key spelled with an
// escape, is ordinary content.
func TestForwardScrubKeepsEncryptedContentOnlyAsDirectLiteralMember(t *testing.T) {
	t.Parallel()
	const fernet = "gAAAAABpQx7Rk3Lw-ak-Zq9VvYb2aXc1Yt0uTsR8pQoNmLkJiHgFeDcBa_ZyXwVuTsRqPoNm=="
	cases := []struct {
		name, body string
		keep       string   // must survive byte-exact ("" = none)
		leaks      []string // must not survive
	}{
		{
			name:  "array-valued encrypted_content",
			body:  `{"input":[{"type":"reasoning","id":"rs_1","encrypted_content":["` + anchorSK + `"]}]}`,
			leaks: []string{anchorSK},
		},
		{
			name:  "escaped key name",
			body:  `{"input":[{"type":"reasoning","id":"rs_1",` + escapedEncryptedContentKey + `:"` + anchorSK + `"}]}`,
			leaks: []string{anchorSK},
		},
		{
			name:  "escaped key name nested in tool output",
			body:  `{"contents":[{"role":"user","parts":[{"functionResponse":{"name":"f","response":{` + escapedEncryptedContentKey + `:"` + anchorSK + `"}}}]}]}`,
			leaks: []string{anchorSK},
		},
		{
			name: "direct literal member stays byte-exact (control)",
			body: `{"input":[{"type":"reasoning","id":"rs_1","encrypted_content":"` + fernet + `"},` +
				`{"type":"function_call_output","call_id":"c1","output":"key ` + anchorSK + `"}]}`,
			keep:  `"encrypted_content":"` + fernet + `"`,
			leaks: []string{anchorSK},
		},
	}
	for _, tc := range cases {
		for _, p := range scrubPaths(tc.body) {
			for _, s := range forwardScrubs {
				t.Run(tc.name+"/"+p.name+"/"+s.name, func(t *testing.T) {
					in := []byte(p.body)
					out := s.fn(in)
					assertScrubbed(t, s.name, in, out, tc.leaks)
					if tc.keep != "" && !bytes.Contains(out, []byte(tc.keep)) {
						t.Errorf("%s: %s not byte-exact:\n%s", s.name, tc.keep, out)
					}
				})
			}
		}
	}
}

// TestProviderScrubLookAlikesInToolOutput: an object shaped like a
// provider-verified one but sitting inside tool output or tool input is not
// at a protocol position, so it is scrubbed like any other content,
// including a password / api_key sibling. Before the fix the shape matched
// at any depth and every sibling went out raw.
func TestProviderScrubLookAlikesInToolOutput(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, body string
	}{
		{
			name: "gemini functionResponse.response carrying thoughtSignature",
			body: `{"contents":[{"role":"model","parts":[{"functionCall":{"name":"read_cfg","args":{}}}]},` +
				`{"role":"user","parts":[{"functionResponse":{"name":"read_cfg","response":{"thoughtSignature":"x","note":"password=` + anchorPW + `","api_key":"` + anchorSK + `"}}}]}]}`,
		},
		{
			name: "anthropic tool_result carrying a thinking block",
			body: `{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"cat","input":{"path":".env"}}]},` +
				`{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":[{"type":"thinking","thinking":"db password=` + anchorPW + `","signature":"s"}]}]}]}`,
		},
		{
			name: "anthropic tool_use.input shaped like a reasoning item",
			body: `{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"write","input":{"type":"reasoning","summary":"x","password":"` + anchorPW + `"}}]}]}`,
		},
		{
			name: "anthropic thinking block in a user turn",
			body: `{"messages":[{"role":"user","content":[{"type":"thinking","thinking":"password=` + anchorPW + `","signature":"s"}]}]}`,
		},
		{
			name: "responses tool output array carrying encrypted_content",
			body: `{"input":[{"type":"function_call_output","call_id":"c1","output":[{"type":"reasoning","encrypted_content":"opaque","text":"api_key=` + anchorSK + `"}]}]}`,
		},
		{
			name: "gemini user part carrying thoughtSignature",
			body: `{"contents":[{"role":"user","parts":[{"text":"my password=` + anchorPW + `","thoughtSignature":"x"}]}]}`,
		},
		{
			name: "extra_content.google outside an assistant tool call",
			body: `{"messages":[{"role":"tool","tool_call_id":"c1","content":[{"type":"text","text":"ok","extra_content":{"google":{"thought_signature":"s","password":"` + anchorPW + `"}}}]}]}`,
		},
	}
	for _, tc := range cases {
		for _, p := range scrubPaths(tc.body) {
			for _, s := range forwardScrubs {
				t.Run(tc.name+"/"+p.name+"/"+s.name, func(t *testing.T) {
					in := []byte(p.body)
					assertScrubbed(t, s.name, in, s.fn(in), []string{anchorPW, anchorSK})
				})
			}
		}
	}
}

// anchoredCases is one row per protocol position in verifiedPositions: a
// realistic request body with a provider-verified field at that position
// (kept byte-exact by ScrubProviderRequest even though it carries a run
// String rewrites) and secrets elsewhere, including a sibling member of
// the same object (scrubbed: only the opaque field is exempt).
var anchoredCases = []struct {
	position string
	body     string
	keep     []string // byte-exact under ScrubProviderRequest
	leaks    []string // must be scrubbed by both forward scrubs
	// storageKeeps: ScrubForward (storage callers) also keeps keep[] -
	// true only for encrypted_content, which String always shields.
	storageKeeps bool
}{
	{
		position: "openai_responses_input_item",
		body: `{"model":"gpt-5.1-codex-mini","store":false,"include":["reasoning.encrypted_content"],"input":[` +
			`{"type":"message","role":"user","content":[{"type":"input_text","text":"check the env"}]},` +
			`{"type":"reasoning","id":"rs_1","summary":[{"type":"summary_text","text":"The config sets token: abc123secretvalue"}],"encrypted_content":"gAAAAABpQx7Rk3Lw-sk-Zq9VvYb2aXc1Yt0uTsR8pQoN=="},` +
			`{"type":"function_call_output","call_id":"c1","output":"key ` + anchorSK + `"}]}`,
		keep:         []string{`"encrypted_content":"gAAAAABpQx7Rk3Lw-sk-Zq9VvYb2aXc1Yt0uTsR8pQoN=="`},
		leaks:        []string{"abc123secretvalue", anchorSK},
		storageKeeps: true,
	},
	{
		position: "anthropic_assistant_content_block",
		body: `{"model":"claude-opus-4-8","messages":[{"role":"user","content":"fix the db"},` +
			`{"role":"assistant","content":[` +
			`{"type":"thinking","thinking":"The .env sets password: ` + anchorPW + ` for the db.","signature":"EqQBCkgIARABGAIiQLv7AKIAABCDEFGHIJKLMNOPsigtail==","note":"api_key=` + anchorSK + `"},` +
			`{"type":"redacted_thinking","data":"EmwKAhgBEgyAKIAABCDEFGHIJKLMNOPxyzRedactedBlob=="},` +
			`{"type":"text","text":"done with ` + anchorGHP + `"}]}]}`,
		keep: []string{
			`"thinking":"The .env sets password: ` + anchorPW + ` for the db."`,
			`"signature":"EqQBCkgIARABGAIiQLv7AKIAABCDEFGHIJKLMNOPsigtail=="`,
			`"data":"EmwKAhgBEgyAKIAABCDEFGHIJKLMNOPxyzRedactedBlob=="`,
		},
		leaks: []string{anchorSK, anchorGHP},
	},
	{
		position: "gemini_model_part",
		body: `{"contents":[{"role":"user","parts":[{"text":"run it"}]},` +
			`{"role":"model","parts":[{"text":"Calling with api_key=AIza` + `SyA0123456789abcdefghijklmnopqrstuv","thoughtSignature":"CiQBAKIAABCDEFGHIJKLMNOPsig=="},` +
			`{"functionCall":{"name":"run","args":{"cmd":"curl -H 'Authorization: Bearer abcdefghijklmnop0123'"}},"thoughtSignature":"CiQBAKIAABCDEFGHIJKLMNOPsig2=="}]},` +
			`{"role":"user","parts":[{"functionResponse":{"name":"run","response":{"out":"export GITHUB_TOKEN=` + anchorGHP + `"}}}]}]}`,
		keep: []string{
			`"thoughtSignature":"CiQBAKIAABCDEFGHIJKLMNOPsig=="`,
			`"thoughtSignature":"CiQBAKIAABCDEFGHIJKLMNOPsig2=="`,
		},
		leaks: []string{"AIza" + "SyA0123456789abcdefghijklmnopqrstuv", "abcdefghijklmnop0123", anchorGHP},
	},
	{
		position: "gemini_openai_compat_tool_call",
		body: `{"model":"gemini-3-pro","messages":[{"role":"user","content":"go"},` +
			`{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"run","arguments":"{\"cmd\":\"echo password=` + anchorPW + `\"}"},` +
			`"extra_content":{"google":{"thought_signature":"CiQBAKIAABCDEFGHIJKLMNOPsnake==","note":"api_key=` + anchorSK + `"}}}]}]}`,
		keep:  []string{`"thought_signature":"CiQBAKIAABCDEFGHIJKLMNOPsnake=="`},
		leaks: []string{anchorPW, anchorSK},
	},
}

// TestProviderScrubKeepsAnchoredVerifiedFields runs every protocol
// position on both paths: the opaque field comes back byte-exact from
// ScrubProviderRequest, and every other secret (including a sibling member
// of the same object) is scrubbed. ScrubForward, which storage callers use,
// still scrubs the field (except encrypted_content).
func TestProviderScrubKeepsAnchoredVerifiedFields(t *testing.T) {
	t.Parallel()
	for _, tc := range anchoredCases {
		for _, p := range scrubPaths(tc.body) {
			t.Run(tc.position+"/"+p.name, func(t *testing.T) {
				in := []byte(p.body)
				out := New().ScrubProviderRequest(in)
				assertScrubbed(t, "ScrubProviderRequest", in, out, tc.leaks)
				for _, k := range tc.keep {
					if !bytes.Contains(out, []byte(k)) {
						t.Errorf("verified field not byte-exact: %s\nout: %s", k, out)
					}
				}
				st := New().ScrubForward(in)
				assertScrubbed(t, "ScrubForward", in, st, tc.leaks)
				for _, k := range tc.keep {
					if got := bytes.Contains(st, []byte(k)); got != tc.storageKeeps {
						t.Errorf("ScrubForward kept %s = %v, want %v (storage posture changed):\n%s", k, got, tc.storageKeeps, st)
					}
				}
			})
		}
	}
}
