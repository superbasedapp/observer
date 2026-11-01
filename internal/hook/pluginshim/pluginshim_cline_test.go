package pluginshim

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// clineDriver exercises the rendered Cline shape the way the Cline CLI's
// plugin host does (cline 3.0.68, live on demo node 1): setup(api, ctx) with
// the session, then beforeModel with the whole request history on every
// model call, and beforeTool per call. FAKE_MODE is switched between calls;
// each observer child inherits it.
const clineDriver = `
const [shimPath, scenario] = process.argv.slice(2);
const E = (await import(shimPath)).default;
const out = { name: E.name, caps: E.manifest && E.manifest.capabilities };
try {
  E.setup({}, { session: { sessionId: "sess-1" }, workspaceInfo: { rootPath: "/w" } });
  const H = E.hooks;
  const u = (id, text) => ({ id, role: "user", content: [{ type: "text", text }, { type: "image", data: "i" }] });
  const tool = (cmd, id) => ({ toolCall: { toolName: "run_commands", toolCallId: id }, input: { commands: [cmd] } });
  if (scenario === "fail") {
    out.first = await H.beforeModel({ request: { messages: [u("m1", "my secret")] } });
    out.tool = await H.beforeTool(tool("rm -rf ~/x", "c1"));
  } else {
    process.env.FAKE_MODE = "deny";
    out.first = await H.beforeModel({ request: { messages: [u("m1", "my secret")] } });
    process.env.FAKE_MODE = "allow";
    out.second = await H.beforeModel({ request: { messages: [u("m1", "my secret"), { id: "a1", role: "assistant", content: "x" }, u("m2", "plain")] } });
    out.third = await H.beforeModel({ request: { messages: [u("m1", "my secret"), u("m2", "plain"), { id: "t1", role: "tool", content: [] }] } }) ?? null;
    process.env.FAKE_MODE = "modify";
    out.redact = await H.beforeModel({ request: { messages: [u("m3", "key sk-123")] } });
    process.env.FAKE_MODE = "allow";
    out.redactLater = await H.beforeModel({ request: { messages: [u("m3", "key sk-123"), { id: "t2", role: "tool", content: [] }] } });
    process.env.FAKE_MODE = "deny";
    out.toolDeny = await H.beforeTool(tool("rm -rf ~/x", "c1"));
    process.env.FAKE_MODE = "ask";
    out.toolAsk = await H.beforeTool(tool("rm -rf ~/x", "c2"));
    process.env.FAKE_MODE = "allow";
    out.toolAllow = (await H.beforeTool(tool("ls", "c3"))) ?? null;
  }
} catch (e) { out.driverError = String(e && e.stack || e); }
console.log(JSON.stringify(out));
`

// runClineShim renders the cline-cli host shim with a fake observer (or a
// missing one) and runs clineDriver.
func runClineShim(t *testing.T, node, scenario, posture string, missingBin bool) (map[string]any, []string, string) {
	t.Helper()
	dir := t.TempDir()
	fake := filepath.Join(dir, "observer")
	if err := os.WriteFile(fake, []byte(fakeObserver), 0o755); err != nil {
		t.Fatal(err)
	}
	bin := fake
	if missingBin {
		bin = filepath.Join(dir, "no-such-observer")
	}
	posturePath := filepath.Join(dir, "guard-posture.json")
	if posture != "" {
		if err := os.WriteFile(posturePath, []byte(posture), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h, ok := HostFor("cline-cli")
	if !ok || h.Shape != ShapeCline || !h.Ask || h.File() != "superbased-observer-guard.js" {
		t.Fatalf("cline-cli host row = %+v", h)
	}
	h.GateMS, h.MarginMS = 3000, 300
	shim, err := Render(h, RenderOptions{
		Events: map[string]string{"beforeModel": "prompt_gate", "beforeTool": "tool_gate"}, Bin: bin,
		PosturePath: posturePath, SpoolPath: filepath.Join(dir, "guard-hookfail.jsonl"), PostureSchema: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	shimPath := filepath.Join(dir, "superbased-observer-guard.mjs")
	drvPath := filepath.Join(dir, "driver.mjs")
	if err := os.WriteFile(shimPath, shim, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(drvPath, []byte(clineDriver), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, drvPath, shimPath, scenario)
	cmd.Env = append(os.Environ(), "FAKE_MODE=allow", "FAKE_DIR="+dir, "OBSERVER_BIN=", "OBSERVER_CONFIG=")
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("node driver: %v (%s)", err, raw)
	}
	var out map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(raw), &out); err != nil {
		t.Fatalf("driver output %q: %v", raw, err)
	}
	if e, ok := out["driverError"]; ok {
		t.Fatalf("driver error: %v", e)
	}
	argv, _ := os.ReadFile(filepath.Join(dir, "argv"))
	stdin, _ := os.ReadFile(filepath.Join(dir, "stdin"))
	var calls []string
	for _, l := range strings.Split(strings.TrimSpace(string(argv)), "\n") {
		if l != "" {
			calls = append(calls, l)
		}
	}
	return out, calls, string(stdin)
}

// TestClineShimUnderNode pins the Cline shape's contract, case by case.
func TestClineShimUnderNode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake observer is a POSIX shell script")
	}
	node := shimNode(t)
	out, calls, lastStdin := runClineShim(t, node, "normal", "", false)
	const withheld = "[SuperBased Observer withheld this message from the model]"
	m1Withheld := `{"content":[{"text":"` + withheld + `","type":"text"},{"data":"i","type":"image"}],"id":"m1","role":"user"}`
	cases := []struct {
		key, want string
	}{
		{"name", `"superbased-observer"`},
		{"caps", `["hooks"]`},
		// A denied newest prompt stops the turn and is withheld.
		{"first", `{"messages":[` + m1Withheld + `],"reason":"no rm here","stop":true}`},
		// The stopped message stays in Cline's history: it is withheld again
		// on the next call, the new prompt is judged and passes.
		{"second", `{"messages":[` + m1Withheld + `,{"content":"x","id":"a1","role":"assistant"},{"content":[{"text":"plain","type":"text"},{"data":"i","type":"image"}],"id":"m2","role":"user"}]}`},
		// No new user message: no observer call, the withhold still applies.
		{"third", `{"messages":[` + m1Withheld + `,{"content":[{"text":"plain","type":"text"},{"data":"i","type":"image"}],"id":"m2","role":"user"},{"content":[],"id":"t1","role":"tool"}]}`},
		// A redaction rewrites the message, now and on every later call.
		{"redact", `{"messages":[{"content":[{"text":"redacted text","type":"text"},{"data":"i","type":"image"}],"id":"m3","role":"user"}]}`},
		{"redactLater", `{"messages":[{"content":[{"text":"redacted text","type":"text"},{"data":"i","type":"image"}],"id":"m3","role":"user"},{"content":[],"id":"t2","role":"tool"}]}`},
		{"toolDeny", `{"reason":"no rm here","skip":true}`},
		{"toolAsk", `{"policy":{"autoApprove":false}}`},
		{"toolAllow", `null`},
	}
	for _, c := range cases {
		if got := jsonOf(out[c.key]); got != c.want {
			t.Errorf("%s = %s\nwant %s", c.key, got, c.want)
		}
	}
	// One observer call per NEW user message and per tool call: m1, m2, m3,
	// three tools.
	if len(calls) != 6 {
		t.Errorf("observer calls = %d %q, want 6", len(calls), calls)
	}
	if len(calls) > 0 && !strings.HasPrefix(calls[0], "hook cline-cli beforeModel --max-runtime ") {
		t.Errorf("prompt argv = %q", calls[0])
	}
	if len(calls) > 0 && !strings.HasPrefix(calls[len(calls)-1], "hook cline-cli beforeTool --max-runtime ") {
		t.Errorf("tool argv = %q", calls[len(calls)-1])
	}
	for _, w := range []string{`"session_id":"sess-1"`, `"cwd":"/w"`, `"tool_name":"run_commands"`, `"tool_input":{"commands":["ls"]}`, `"call_id":"c3"`} {
		if !strings.Contains(lastStdin, w) {
			t.Errorf("tool envelope %s missing %s", lastStdin, w)
		}
	}
}

// TestClineShimFailsClosedUnderEnforcement: observer missing while a fresh
// enforced posture is on stops the prompt and skips the call; without the
// posture both pass (fail open), as for every other plugin host.
func TestClineShimFailsClosedUnderEnforcement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake observer is a POSIX shell script")
	}
	node := shimNode(t)
	out, _, _ := runClineShim(t, node, "fail", enforcedPosture, true)
	if got := jsonOf(out["first"]); !strings.Contains(got, `"stop":true`) || !strings.Contains(got, "internal error") {
		t.Errorf("enforced prompt failure = %s, want a stop", got)
	}
	if got := jsonOf(out["tool"]); !strings.Contains(got, `"skip":true`) {
		t.Errorf("enforced tool failure = %s, want a skip", got)
	}
	out, _, _ = runClineShim(t, node, "fail", "", true)
	if got := jsonOf(out["first"]); got != "null" && got != "" {
		if _, has := out["first"]; has {
			t.Errorf("open prompt failure = %s, want undefined", got)
		}
	}
	if _, has := out["tool"]; has {
		t.Errorf("open tool failure = %s, want undefined", jsonOf(out["tool"]))
	}
}
