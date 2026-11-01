package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// hook_fu161_test.go pins FU-161 (tracker R-202, a guard bypass): a gate
// payload that starts with a UTF-8 byte order mark (a .NET / PowerShell
// stdin writer on a UTF-8 console prepends one) used to reach the Claude
// Code pre-tool guard as an untrimmed copy, fail its decode and be approved
// unevaluated under guard enforce. Every stdin-reading gate receiver is
// driven here through runHookInvocation's own dispatch (fu161Dispatch:
// stdin a pipe, the invocation's real failure plan, no watchdog), on a
// guard-enforce node and a guard-observe node:
//
//   - a BOM-prefixed payload a rule denies gets exactly the answer the
//     same payload gets without the BOM, and that answer is not the allow;
//   - a BOM-prefixed allowed payload gets its normal answer;
//   - valid JSON whose fields the gate reads do not decode (a tool_input
//     that is not an object, an operand or a prompt that is not a string)
//     fails closed under enforce exactly as a payload that is not JSON
//     does (the hookFailClosed KindUnparseable path), and keeps today's
//     answer (the same as not JSON) outside enforce.

// fu161Secret is a prompt the prompt gate stops (an Anthropic API key
// shape, rule R-172).
const fu161Secret = "please deploy with sk-ant-api03-AbCd1234EfGh5678IjKl9MnOpQrStUvWx this time"

// fu161Result is one invocation's observable answer.
type fu161Result struct {
	Stdout string
	Exits  []int
}

// fu161Case is one receiver: how to build its payloads in a node dir.
type fu161Case struct {
	tool, event string
	// deny / allow build a payload a rule stops / lets through; bad builds
	// valid JSON a field of which the gate cannot decode.
	deny, allow, bad func(dir string) string
	// env is set for every run ("<HOME>" is the node's home).
	env map[string]string
	// cwdVariant: also run deny with a JSON-escaped Windows cwd.
	cwdVariant bool
	// freshNodes: every run gets its own node. A prompt gate needs it: its
	// resend-to-confirm state would let a second identical prompt through.
	freshNodes bool
	// today builds the payload whose answer outside enforce is what an
	// undecodable payload got before FU-161 (nil: a payload that is not
	// JSON). The Copilot replay needs the allowed call: a payload that is
	// not JSON is never classified as Copilot's.
	today func(dir string) string
}

// fu161Node is one node: a config (guard enforce or observe), its posture,
// a home.
type fu161Node struct{ dir, home, cp string }

func fu161NewNode(t *testing.T, enforced bool) fu161Node {
	t.Helper()
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	mode := "observe"
	if enforced {
		mode = "enforce"
	}
	cp := filepath.Join(dir, "config.toml")
	writeFileT(t, cp, fmt.Sprintf("[observer]\ndb_path = %q\n[observer.hooks]\nauto_register = false\n[guard]\nenabled = true\nmode = %q\n[guard.prompt]\nenabled = true\nhook_lane = true\n",
		filepath.Join(dir, "o.db"), mode))
	if enforced {
		writePosture(t, cp, enforcedPosture)
	} else {
		writePosture(t, cp, guardposture.Posture{Enforced: false, Source: guardposture.SourceLocal})
	}
	return fu161Node{dir: dir, home: home, cp: cp}
}

// fu161Dispatch is runHookInvocation's receiver dispatch for one (tool,
// event) without its watchdog (a loaded test machine must not turn a slow
// answer into a timeout block): the binding-driven tool gate, the tool's
// receiver, or the binding route, reading os.Stdin as production does.
func fu161Dispatch(tool, event, configPath string) {
	ctx := context.Background()
	label := tool
	if event != "" {
		label = tool + ":" + event
	}
	if b, ok := standaloneToolGate(tool, event); ok {
		handleToolGateHook(tool, label, b, os.Stdin, configPath)
		return
	}
	if fn, ok := hookReceivers[tool]; ok {
		fn(ctx, event, configPath)
		return
	}
	dispatchWithoutReceiver(ctx, tool, event, label, configPath)
}

// fu161Runner runs a case's invocations, each with stdin a pipe and the
// invocation's own failure plan, on a node per posture (or a fresh node
// per run), and returns the answer with the node directory replaced by
// <DIR> so answers of two nodes compare.
type fu161Runner struct {
	t     *testing.T
	c     fu161Case
	nodes map[bool]fu161Node
}

func (r *fu161Runner) run(enforced bool, body func(dir string) string, bom bool) fu161Result {
	t := r.t
	t.Helper()
	n, ok := r.nodes[enforced]
	if !ok || r.c.freshNodes {
		n = fu161NewNode(t, enforced)
		r.nodes[enforced] = n
	}
	setTestHome(t, n.home)
	for k, v := range r.c.env {
		t.Setenv(k, strings.ReplaceAll(v, "<HOME>", n.home))
	}
	event := canonicalHookEvent(r.c.tool, r.c.event)
	payload := body(n.dir)
	if bom {
		payload = "\xef\xbb\xbf" + payload
	}
	h := newFailureHarness(t, resolveHookFailurePlan(r.c.tool, event, n.cp))
	withStdinT(t, payload, func() { fu161Dispatch(r.c.tool, event, n.cp) })
	out := h.stdout.String()
	for _, d := range []string{n.dir, jsonEscaped(n.dir)} {
		out = strings.ReplaceAll(out, d, "<DIR>")
	}
	return fu161Result{Stdout: out, Exits: h.exitCodes()}
}

func jsonEscaped(s string) string {
	b, _ := json.Marshal(s)
	return strings.Trim(string(b), `"`)
}

// fu161Check runs c's matrix.
func fu161Check(t *testing.T, c fu161Case) {
	t.Helper()
	notJSON := func(string) string { return "this is not json" }
	r := &fu161Runner{t: t, c: c, nodes: map[bool]fu161Node{}}

	deny := r.run(true, c.deny, false)
	allow := r.run(true, c.allow, false)
	if reflect.DeepEqual(deny, allow) {
		t.Fatalf("%s %s: the deny fixture is answered like the allowed one (%+v); it does not exercise the gate", c.tool, c.event, deny)
	}
	if got := r.run(true, c.deny, true); !reflect.DeepEqual(got, deny) {
		t.Errorf("BOM + deny: %+v\nwant the plain answer %+v", got, deny)
	}
	if got := r.run(true, c.allow, true); !reflect.DeepEqual(got, allow) {
		t.Errorf("BOM + allowed: %+v\nwant the plain answer %+v", got, allow)
	}
	if c.cwdVariant {
		winCwd := func(dir string) string {
			return strings.ReplaceAll(c.deny(dir), jsonEscaped(dir), jsonEscaped(`C:\lc\proj`))
		}
		if got := r.run(true, winCwd, true); reflect.DeepEqual(got, allow) {
			t.Errorf("BOM + JSON-escaped C:\\ cwd + deny is answered like the allowed call: %+v", got)
		}
	}
	failClosed := r.run(true, notJSON, false)
	if reflect.DeepEqual(failClosed, allow) {
		t.Fatalf("a payload that is not JSON is answered like the allowed call under enforce: %+v", failClosed)
	}
	if got := r.run(true, c.bad, false); !reflect.DeepEqual(got, failClosed) {
		t.Errorf("undecodable under enforce: %+v\nwant the fail-closed answer %+v", got, failClosed)
	}
	if got := r.run(true, c.bad, true); !reflect.DeepEqual(got, failClosed) {
		t.Errorf("BOM + undecodable under enforce: %+v\nwant the fail-closed answer %+v", got, failClosed)
	}
	today := c.today
	if today == nil {
		today = notJSON
	}
	if got, want := r.run(false, c.bad, false), r.run(false, today, false); !reflect.DeepEqual(got, want) {
		t.Errorf("undecodable outside enforce: %+v\nwant today's answer %+v", got, want)
	}
}

// fu161Mark replaces in a payload the JSON value that holds a marker (the
// tool input object, or the operand string inside a JSON-encoded string)
// with the string "x": a tool input of the wrong type.
func fu161Mark(t *testing.T, payload string, markers ...string) string {
	t.Helper()
	var v any
	dec := json.NewDecoder(strings.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	holds := func(x any) bool {
		switch t := x.(type) {
		case string:
			for _, m := range markers {
				if strings.Contains(t, m) {
					return true
				}
			}
		case []any:
			for _, e := range t {
				if s, ok := e.(string); ok {
					for _, m := range markers {
						if strings.Contains(s, m) {
							return true
						}
					}
				}
			}
		}
		return false
	}
	var walk func(x any) bool
	walk = func(x any) bool {
		m, ok := x.(map[string]any)
		if !ok {
			return false
		}
		for k, child := range m {
			if cm, ok := child.(map[string]any); ok {
				for _, leaf := range cm {
					if holds(leaf) {
						m[k] = "x"
						return true
					}
				}
				if walk(cm) {
					return true
				}
			}
			if s, ok := child.(string); ok && holds(s) && strings.HasPrefix(strings.TrimSpace(s), "{") {
				// A JSON-encoded tool input (Copilot CLI's toolArgs).
				m[k] = "x"
				return true
			}
		}
		return false
	}
	if !walk(v) {
		t.Fatalf("no tool input holding %v in %s", markers, payload)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// fu161Allowed rewrites a deny fixture into the same call on a harmless
// operand.
func fu161Allowed(s string) string {
	r := strings.NewReplacer(
		"rm -rf ~/", "echo fu161-ok",
		"~/.ssh/authorized_keys", "notes/fu161.txt",
		"~/.ssh/id_rsa", "notes/fu161.txt",
	)
	return r.Replace(s)
}

// TestFU161ToolGatesJudgeBOMAndFailClosedOnUndecodable: every served tool
// gate (read from the registry), with the BOM and the JSON-escaped C:\ cwd
// variants beside TestToolGateReceiversAnswerEndToEnd's fixtures.
func TestFU161ToolGatesJudgeBOMAndFailClosedOnUndecodable(t *testing.T) {
	for _, g := range servedToolGates(t) {
		if g.b.NativeEvent == "pre_mcp_tool_use" {
			continue // no builtin rule blocks an MCP call (TestToolGateReceiversAnswerEndToEnd)
		}
		g := g
		t.Run(g.tool+" "+g.b.NativeEvent, func(t *testing.T) {
			deny := func(dir string) string { return toolGateE2EFixture(g.tool, g.b.NativeEvent, g.b.Dialect, dir) }
			fu161Check(t, fu161Case{
				tool: g.tool, event: g.b.NativeEvent,
				deny:  deny,
				allow: func(dir string) string { return fu161Allowed(deny(dir)) },
				bad: func(dir string) string {
					return fu161Mark(t, deny(dir), "rm -rf ~/", "~/.ssh/")
				},
				cwdVariant: true,
			})
		})
	}
}

// TestFU161ClaudeCodeReceivers: Claude Code's own receiver (pre-tool and
// user-prompt-submit, the events that judge; permission-request and the
// other action events only capture and always approve), and the Copilot
// CLI runtime's Claude-shaped PreToolUse replay through that receiver
// (served as copilot-cli's replay tool gate while Observer's own
// copilot-cli hook is not registered, G2).
func TestFU161ClaudeCodeReceivers(t *testing.T) {
	bash := func(tool, cmd string) func(string) string {
		return func(dir string) string {
			return fmt.Sprintf(`{"session_id":"s1","cwd":%q,"hook_event_name":"PreToolUse","tool_name":%q,"tool_input":{"command":%q}}`, dir, tool, cmd)
		}
	}
	badBash := func(tool string) func(string) string {
		return func(dir string) string {
			return fmt.Sprintf(`{"session_id":"s1","cwd":%q,"hook_event_name":"PreToolUse","tool_name":%q,"tool_input":"x"}`, dir, tool)
		}
	}
	prompt := func(text string) func(string) string {
		return func(dir string) string {
			return fmt.Sprintf(`{"session_id":"s1","cwd":%q,"hook_event_name":"UserPromptSubmit","prompt":%q}`, dir, text)
		}
	}
	for _, c := range []fu161Case{
		{tool: "claude-code", event: "pre-tool", deny: bash("Bash", "rm -rf ~/"), allow: bash("Bash", "echo fu161-ok"), bad: badBash("Bash"), cwdVariant: true},
		{
			tool: "claude-code", event: "user-prompt-submit", deny: prompt(fu161Secret), allow: prompt("hello there"),
			bad: func(dir string) string {
				return fmt.Sprintf(`{"session_id":"s1","cwd":%q,"hook_event_name":"UserPromptSubmit","prompt":5}`, dir)
			},
			freshNodes: true,
		},
		{
			tool: "claude-code", event: "pre-tool", deny: bash("bash", "rm -rf ~/"), allow: bash("bash", "echo fu161-ok"), bad: badBash("bash"),
			env:   map[string]string{"COPILOT_CLI": "1", "COPILOT_HOOK_DIR": "<HOME>/.copilot/hooks"},
			today: bash("bash", "echo fu161-ok"), cwdVariant: true,
		},
	} {
		c := c
		name := c.event
		if c.env != nil {
			name = "copilot-cli replay " + c.event
		}
		t.Run(name, func(t *testing.T) { fu161Check(t, c) })
	}
}

// TestFU161OwnReceivers: the receivers with a gate of their own beside the
// tool-gate table: Cursor (a before* permission event and
// beforeSubmitPrompt), Codex, Copilot CLI and Antigravity prompts, and the
// plugin-shim hosts' Go receiver (every wired plugin tool gate from the
// registry, and a plugin prompt gate).
func TestFU161OwnReceivers(t *testing.T) {
	genericPrompt := func(event string) func(text any) func(string) string {
		return func(text any) func(string) string {
			return func(dir string) string {
				b, _ := json.Marshal(text)
				return fmt.Sprintf(`{"session_id":"s1","sessionId":"s1","cwd":%q,"hook_event_name":%q,"prompt":%s}`, dir, event, b)
			}
		}
	}
	cursorShell := func(cmd any) func(string) string {
		return func(dir string) string {
			b, _ := json.Marshal(cmd)
			return fmt.Sprintf(`{"conversation_id":"s1","generation_id":"g1","hook_event_name":"beforeShellExecution","command":%s,"cwd":%q,"workspace_roots":[%q]}`, b, dir, dir)
		}
	}
	cursorPrompt := func(text any) func(string) string {
		return func(dir string) string {
			b, _ := json.Marshal(text)
			return fmt.Sprintf(`{"conversation_id":"s1","generation_id":"g1","hook_event_name":"beforeSubmitPrompt","prompt":%s,"workspace_roots":[%q]}`, b, dir)
		}
	}
	agy := func(text string, badPath bool) func(string) string {
		return func(dir string) string {
			tp := filepath.Join(dir, "transcript.jsonl")
			step, _ := json.Marshal(map[string]string{"type": "USER_INPUT", "content": "<USER_REQUEST>" + text + "</USER_REQUEST>"})
			if err := os.WriteFile(tp, append(step, '\n'), 0o600); err != nil {
				panic(err)
			}
			if badPath {
				return `{"conversationId":"s1","transcriptPath":5}`
			}
			return fmt.Sprintf(`{"conversationId":"s1","transcriptPath":%q}`, tp)
		}
	}
	cases := map[string]fu161Case{
		"cursor beforeShellExecution": {tool: "cursor", event: "beforeShellExecution", deny: cursorShell("rm -rf ~/"), allow: cursorShell("echo fu161-ok"), bad: cursorShell(5), cwdVariant: true},
		"cursor beforeSubmitPrompt":   {tool: "cursor", event: "beforeSubmitPrompt", deny: cursorPrompt(fu161Secret), allow: cursorPrompt("hello there"), bad: cursorPrompt(5), freshNodes: true},
		"codex UserPromptSubmit": {
			tool: "codex", event: "UserPromptSubmit",
			deny: genericPrompt("UserPromptSubmit")(fu161Secret), allow: genericPrompt("UserPromptSubmit")("hello there"), bad: genericPrompt("UserPromptSubmit")(5),
			freshNodes: true,
		},
		"copilot-cli userPromptSubmitted": {
			tool: "copilot-cli", event: "userPromptSubmitted",
			deny: genericPrompt("userPromptSubmitted")(fu161Secret), allow: genericPrompt("userPromptSubmitted")("hello there"), bad: genericPrompt("userPromptSubmitted")(5),
			freshNodes: true,
		},
		"antigravity-cli PreInvocation": {
			tool: "antigravity-cli", event: "PreInvocation", deny: agy(fu161Secret, false), allow: agy("hello there", false), bad: agy("hello there", true),
			freshNodes: true,
		},
		"opencode chat.message (plugin prompt)": {
			tool: "opencode", event: "chat.message",
			deny:       pluginPromptFixture(fu161Secret),
			allow:      pluginPromptFixture("hello there"),
			bad:        pluginPromptFixture(5),
			freshNodes: true,
		},
	}
	plugins := 0
	for _, c := range integration.Capabilities() {
		for _, b := range c.Hook.Bindings {
			if b.Cap != integration.HookCapToolGate || !b.Wired || b.Dialect != hook.PluginDialectToolGate {
				continue
			}
			plugins++
			native := pluginShellTool[c.Tool]
			if native == "" {
				native = "bash"
			}
			tool, event := c.Tool, b.NativeEvent
			env := func(input string) func(string) string {
				return func(dir string) string {
					return fmt.Sprintf(`{"host":%q,"event":%q,"session_id":"s1","cwd":%q,"pid":4242,"tool_name":%q,"tool_input":%s,"call_id":"c1"}`, tool, event, dir, native, input)
				}
			}
			cases["plugin tool gate "+tool+" "+event] = fu161Case{
				tool: tool, event: event,
				deny: env(`{"command":"rm -rf ~/"}`), allow: env(`{"command":"echo fu161-ok"}`), bad: env(`"x"`), cwdVariant: true,
			}
		}
	}
	if plugins == 0 {
		t.Fatal("the registry has no wired plugin tool gate; this test no longer covers the plugin receiver")
	}
	for name, c := range cases {
		c := c
		t.Run(name, func(t *testing.T) { fu161Check(t, c) })
	}
}

// pluginPromptFixture is a plugin-shim prompt envelope (opencode
// chat.message) carrying text as its prompt (any JSON value).
func pluginPromptFixture(text any) func(string) string {
	return func(dir string) string {
		b, _ := json.Marshal(text)
		return fmt.Sprintf(`{"host":"opencode","event":"chat.message","session_id":"s1","cwd":%q,"pid":4242,"prompt":%s}`, dir, b)
	}
}

// TestFU161ClaudeStreamIsTrimmedOnce pins the stream half of the fix: the
// bytes claudeCodeHookPayload hands every claude-code handler are the
// BOM-free payload, so no handler decodes an untrimmed copy.
func TestFU161ClaudeStreamIsTrimmedOnce(t *testing.T) {
	payload := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`
	stdin, body, _ := claudeCodeHookPayload(strings.NewReader("\xef\xbb\xbf"+payload), "pre-tool", "")
	if string(body) != payload {
		t.Errorf("classified body = %q", body)
	}
	got, truncated := readHookBodyDetectTruncation(stdin, promptSubmitBodyLimit)
	if truncated || !bytes.Equal(got, []byte(payload)) {
		t.Errorf("handler stream = %q (truncated %v), want the BOM-free payload", got, truncated)
	}
}
