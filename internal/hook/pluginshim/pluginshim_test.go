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
	"time"
)

func profileOf(t *testing.T, shim []byte) profile {
	t.Helper()
	const start = "const PROFILE = "
	i := bytes.Index(shim, []byte(start))
	if i < 0 {
		t.Fatal("rendered shim has no PROFILE literal")
	}
	rest := shim[i+len(start):]
	j := bytes.Index(rest, []byte(";\n"))
	if j < 0 {
		t.Fatal("PROFILE literal is not terminated")
	}
	var p profile
	if err := json.Unmarshal(rest[:j], &p); err != nil {
		t.Fatalf("PROFILE literal is not JSON: %v", err)
	}
	return p
}

func TestRenderBakesProfile(t *testing.T) {
	h, _ := HostFor("opencode")
	got, err := Render(h, RenderOptions{
		Events: map[string]string{"tool.execute.before": "tool_gate", "chat.message": "prompt_gate"},
		Bin:    `C:\Program Files\obs "x"\observer.exe`, Config: "/c/config.toml",
		PosturePath: "/c/guard-posture.json", SpoolPath: "/c/guard-hookfail.jsonl", PostureSchema: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got, []byte(profilePlaceholder)) {
		t.Fatal("placeholder survived")
	}
	if !LooksLikeObserverShim(got) {
		t.Fatal("rendered shim does not carry the marker")
	}
	p := profileOf(t, got)
	if p.Tool != "opencode" || p.Shape != ShapeOpenCode || p.Bin != `C:\Program Files\obs "x"\observer.exe` ||
		p.Events["tool.execute.before"] != "tool_gate" || p.GateMS != defaultGateMS || p.MarginMS != defaultMarginMS ||
		p.PostureSchema != 1 || p.Spool != "/c/guard-hookfail.jsonl" {
		t.Fatalf("profile = %+v", p)
	}
	if empty, _ := Render(h, RenderOptions{}); profileOf(t, empty).Bin != "observer" {
		t.Fatal("empty Bin must default to the PATH lookup")
	}
}

func TestHostsTable(t *testing.T) {
	shapes := map[string]bool{ShapeOpenCode: true, ShapePi: true, ShapeOpenClaw: true, ShapeCordis: true, ShapeCommandCode: true, ShapeCline: true}
	env := map[string]string{}
	getenv := func(k string) string { return env[k] }
	for _, tool := range Tools() {
		h, _ := HostFor(tool)
		if h.Tool != tool || !shapes[h.Shape] {
			t.Errorf("%s: bad row %+v", tool, h)
		}
		dir, err := h.Dir("/home/u", getenv)
		if h.Writable() != (err == nil) {
			t.Errorf("%s: Writable=%v but Dir err=%v", tool, h.Writable(), err)
		}
		if !h.Writable() && h.Note == "" {
			t.Errorf("%s: a host without an install location must say why", tool)
		}
		if err == nil && !strings.HasPrefix(dir, filepath.FromSlash("/home/u/")) {
			t.Errorf("%s: dir %q not under home", tool, dir)
		}
	}
	cases := []struct {
		tool string
		env  map[string]string
		want string
	}{
		{"opencode", nil, "/home/u/.config/opencode/plugins"},
		{"opencode", map[string]string{"XDG_CONFIG_HOME": "/x"}, "/x/opencode/plugins"},
		{"kilo-code-cli", nil, "/home/u/.config/kilo/plugin"},
		{"pi", nil, "/home/u/.pi/agent/extensions"},
		{"pi", map[string]string{"PI_CODING_AGENT_DIR": "/p"}, "/p/extensions"},
		{"command-code", nil, "/home/u/.commandcode/mods"},
		{"cline-cli", nil, "/home/u/.cline/plugins"},
		{"cline-cli", map[string]string{"CLINE_DIR": "/c"}, "/c/plugins"},
	}
	for _, c := range cases {
		env = c.env
		h, _ := HostFor(c.tool)
		got, err := h.Dir("/home/u", getenv)
		if err != nil || got != filepath.FromSlash(c.want) {
			t.Errorf("%s %v: Dir = %q, %v; want %q", c.tool, c.env, got, err, c.want)
		}
	}
}

func TestWriteRemove(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "plugins")
	h, _ := HostFor("pi")
	path, err := Write(dir, h, RenderOptions{Events: map[string]string{"tool_call": "tool_gate"}})
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Fatalf("stat %s: %v %v", path, fi, err)
	}
	if err := Remove(dir, h); err != nil {
		t.Fatal(err)
	}
	if err := Remove(dir, h); err != nil {
		t.Fatalf("second Remove: %v", err)
	}
}

// fakeObserver is a stand-in `observer` for the node tests: it records its
// argv and stdin, then answers per FAKE_MODE.
const fakeObserver = `#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_DIR/argv"
cat > "$FAKE_DIR/stdin"
case "$FAKE_MODE" in
allow) echo '{"decision":"allow","enforced":false}' ;;
allowenf) echo '{"decision":"allow","enforced":true}' ;;
deny) echo 'observer-hook: noise'; echo '{"decision":"deny","reason":"no rm here","enforced":true}' ;;
ask) echo '{"decision":"ask","reason":"confirm this","enforced":true}' ;;
modify) echo '{"decision":"modify","prompt":"redacted text","enforced":true}' ;;
warn) echo '{"decision":"allow","message":"observer: heads up","enforced":true}' ;;
garbage) echo 'not json' ;;
hang) exec sleep 20 ;;
crash) exit 3 ;;
handled) echo '{"action":"handled","message":"cc blocked"}' ;;
context) echo '{"context":"guard: check the diff"}' ;;
inactive) echo 'observer-hook: x: the x adapter is not active on this machine; allowing without recording' >&2; echo '{"decision":"approve"}' ;;
esac
`

// driver exercises one shape adapter of a rendered shim and prints the
// observable outcome as JSON.
const driver = `
const [shimPath, shape, event] = process.argv.slice(2);
const mod = await import(shimPath);
const E = mod.default;
let out;
try {
  if (shape === "opencode" && process.env.FAKE_CONTRACT === "v2") {
    // The v2 contract (OpenCode 2.x): setup(context) registers hooks on the
    // context's domains; the driver records them and fires each like the
    // host does (@opencode-ai/cli 0.0.0-beta-19271).
    const reg = {};
    const subs = [];
    // FAKE_V2_HOOK: a host whose registration fails (throw, reject, a lazy
    // value without dispose, or no such domain).
    const fail = process.env.FAKE_V2_HOOK || "";
    const domain = (name) => ({ hook: (n, fn) => {
      if (fail === "throw") throw new Error("no such hook");
      if (fail === "reject") return Promise.reject(new Error("no such hook"));
      if (fail === "lazy") return { _tag: "Effect" };
      reg[name + "." + n] = fn;
      return Promise.resolve({ dispose: async () => {} });
    } });
    const ctx = { location: { directory: "/w" }, event: { subscribe: async (fn) => { subs.push(fn); return { dispose: async () => {} }; } } };
    if (fail !== "nodomain") { ctx.tool = domain("tool"); ctx.session = domain("session"); }
    const errs = [];
    const origErr = console.error;
    console.error = (...a) => { errs.push(a.join(" ")); };
    await E.setup(ctx);
    console.error = origErr;
    const hooks = Object.keys(reg).sort();
    if (fail) {
      out = { hooks, errs };
    } else if (event === "chat.message") {
      const ev = { sessionID: "s1", messageID: "m1", prompt: { text: "my secret", files: [] }, metadata: {}, delivery: "steer" };
      let threw = null;
      try { await reg["session.prompt"](ev); } catch (e) { threw = String(e && e.message); }
      out = { prompt: ev.prompt, threw, hooks };
    } else if (event === "tool.execute.after") {
      const ev = { tool: "bash", sessionID: "s1", agent: "build", messageID: "m1", id: "c1", input: { command: "ls" }, status: "completed", result: { output: "out", content: [] } };
      await reg["tool.execute.after"](ev);
      out = { output: ev.result.output, hooks };
    } else if (event === "session.idle") {
      for (const fn of subs) fn({ type: "session.idle", properties: { sessionID: "s1" } });
      await new Promise((r) => setTimeout(r, 500));
      out = { subs: subs.length, hooks };
    } else {
      // FAKE_V2_ARGS: a host build that names the tool input "args".
      const ev = { tool: "bash", sessionID: "s1", agent: "build", messageID: "m1", id: "c1" };
      ev[process.env.FAKE_V2_ARGS ? "args" : "input"] = { command: "rm -rf ~/x" };
      try { await reg["tool.execute.before"](ev); out = { ok: true, hooks }; }
      catch (e) { out = { threw: String(e && e.message), hooks }; }
    }
  } else if (shape === "opencode" && process.env.FAKE_CONTRACT === "v1both") {
    // FU-188: a v1 host (Kilo CLI 7.8.x) that calls setup with its v1 input
    // as well as server, in FAKE_ORDER. Only server's hooks may exist.
    const input = { directory: "/w", worktree: "/w", project: { id: "p" }, client: {}, $: () => {} };
    const errs = [];
    const origErr = console.error;
    console.error = (...a) => { errs.push(a.join(" ")); };
    let hooks;
    if (process.env.FAKE_ORDER === "server-first") {
      hooks = await E.server(input);
      await E.setup(input);
    } else {
      await E.setup(input);
      hooks = await E.server(input);
    }
    console.error = origErr;
    let threw = null;
    try { await hooks["tool.execute.before"]({ tool: "bash", sessionID: "s1", callID: "c1" }, { args: { command: "rm -rf ~/x" } }); } catch (e) { threw = String(e && e.message); }
    out = { hooks: Object.keys(hooks).sort(), threw, errs };
  } else if (shape === "opencode") {
    // client: the host's v1 SDK client (@opencode-ai/sdk createOpencodeClient);
    // tui.showToast({body}) records what the developer would see.
    const toasts = [];
    const client = { tui: { showToast: async (o) => { toasts.push(o); return { data: true }; } } };
    const hooks = await E.server({ directory: "/w", client });
    if (event === "chat.message") {
      const o = { parts: [{ type: "text", text: "my secret" }, { type: "file" }, { type: "text", text: "tail" }] };
      let threw = null;
      try { await hooks["chat.message"]({ sessionID: "s1" }, o); } catch (e) { threw = String(e && e.message); }
      // A client whose toast throws or rejects must never break the hook.
      const broken = {};
      for (const [k, showToast] of [["throws", () => { throw new Error("boom"); }], ["rejects", async () => { throw new Error("boom"); }], ["absent", undefined]]) {
        const h2 = await E.server({ directory: "/w", client: showToast ? { tui: { showToast } } : {} });
        const o2 = { parts: [{ type: "text", text: "my secret" }] };
        let t2 = null;
        try { await h2["chat.message"]({ sessionID: "s1" }, o2); } catch (e) { t2 = "threw: " + String(e && e.message); }
        broken[k] = t2 || o2.parts[0].text;
      }
      out = { parts: o.parts, toasts, broken, threw };
    } else {
      try { await hooks["tool.execute.before"]({ tool: "bash", sessionID: "s1", callID: "c1" }, { args: { command: "rm -rf ~/x" } }); out = toasts.length ? { ok: true, toasts } : { ok: true }; }
      catch (e) { out = { threw: String(e && e.message), toasts }; }
    }
  } else if (shape === "pi") {
    // FAKE_UI: none (print / json mode, ctx.hasUI false), yes / no (a UI
    // whose confirm answers that way). notify / confirm calls are recorded.
    const h = {};
    E({ on: (n, fn) => { h[n] = fn; } });
    const ui = process.env.FAKE_UI || "none";
    const notes = [];
    const confirms = [];
    const ctx = {
      cwd: "/w", sessionManager: { getSessionId: () => "s1" }, hasUI: ui !== "none",
      ui: {
        notify: (m, l) => { notes.push({ level: l, message: m }); },
        confirm: async (title, message, opts) => { confirms.push({ title, message, timeout: opts && opts.timeout }); return ui === "yes"; },
      },
    };
    if (event === "input") {
      // extension-sourced input is never gated (it would recurse).
      const ext = await h.input({ type: "input", text: "from an extension", source: "extension" }, ctx);
      const ret = await h.input({ type: "input", text: "my secret", source: "interactive", images: [{ type: "image" }] }, ctx);
      out = { ret, ext, notes, confirms };
    } else {
      out = { ret: (await h.tool_call({ toolName: "bash", input: { command: "rm -rf ~/x" }, toolCallId: "c1" }, ctx)) ?? null, notes, confirms };
    }
  } else if (shape === "openclaw") {
    let fn, opts;
    E.register({ on: (n, f, o) => { fn = f; opts = o; } });
    out = { ret: (await fn({ toolName: "exec", params: { command: "rm -rf ~/x" }, toolCallId: "c1" }, { sessionId: "s1" })) ?? null, timeoutMs: opts.timeoutMs };
  } else if (shape === "cordis") {
    let fn;
    E.apply({ on: (n, f) => { fn = f; } });
    out = { ret: await fn({ name: "bash", input: { command: "rm -rf ~/x" }, sessionId: "s1" }, () => "NEXT") };
  } else if (shape === "commandcode") {
    let h;
    E({ hooks: (x) => { h = x; } });
    if (event === "transformInput") out = { ret: h.transformInput({ text: "my secret" }) };
    else out = { ret: (await h.beforeToolCall({ toolCallId: "c1", toolName: "bash", input: { command: "rm -rf ~/x" } })) ?? null };
  }
} catch (e) { out = { driverError: String(e && e.stack || e) }; }
console.log(JSON.stringify(out));
`

type shimRun struct {
	out   map[string]any
	argv  string
	stdin string
	spool string
}

func runShim(t *testing.T, node, tool, event, cap, mode string, posture string, gateMS int, missingBin bool, extraEnv ...string) shimRun {
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
	spoolPath := filepath.Join(dir, "guard-hookfail.jsonl")
	h, _ := HostFor(tool)
	h.GateMS, h.MarginMS = gateMS, 300
	shim, err := Render(h, RenderOptions{
		Events: map[string]string{event: cap}, Bin: bin, Config: "/cfg/config.toml",
		PosturePath: posturePath, SpoolPath: spoolPath, PostureSchema: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	shimPath := filepath.Join(dir, "shim.mjs")
	drvPath := filepath.Join(dir, "driver.mjs")
	if err := os.WriteFile(shimPath, shim, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(drvPath, []byte(driver), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, drvPath, shimPath, h.Shape, event)
	cmd.Env = append(os.Environ(), "FAKE_MODE="+mode, "FAKE_DIR="+dir, "OBSERVER_BIN=", "OBSERVER_CONFIG=")
	cmd.Env = append(cmd.Env, extraEnv...)
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("node driver: %v (%s)", err, raw)
	}
	var r shimRun
	if err := json.Unmarshal(bytes.TrimSpace(raw), &r.out); err != nil {
		t.Fatalf("driver output %q: %v", raw, err)
	}
	if e, ok := r.out["driverError"]; ok {
		t.Fatalf("driver error: %v", e)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "argv"))
	r.argv = string(b)
	b, _ = os.ReadFile(filepath.Join(dir, "stdin"))
	r.stdin = string(b)
	b, _ = os.ReadFile(spoolPath)
	r.spool = string(b)
	return r
}

func jsonOf(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// enforcedPosture is a FRESH enforced posture (T-050: the shim ignores a
// stale one).
var enforcedPosture = postureAt(time.Now())

// postureAt is an enforced posture for both gates written at at.
func postureAt(at time.Time) string {
	return `{"schema":1,"enforced":true,"gate_caps":["tool_gate","prompt_gate"],"written_at":"` + at.UTC().Format(time.RFC3339Nano) + `"}`
}

// Outputs are compared after a Go re-marshal, so object keys are sorted.

// TestShimUnderNode runs the rendered shim under a real Node with a fake
// observer: every host contract, every reply, and every failure kind under
// enforced and non-enforced posture (hook-parity audit section 5.7).
func TestShimUnderNode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake observer is a POSIX shell script")
	}
	node := shimNode(t)
	cases := []struct {
		name, tool, event, cap, mode, posture string
		missing                               bool
		ui                                    string // pi FAKE_UI ("" = none)
		want                                  string // substring of the driver output JSON
		spool                                 string // substring of the spool ("" = must be empty)
	}{
		// OpenCode / Kilo: throw = deny.
		{"opencode allow", "opencode", "tool.execute.before", "tool_gate", "allow", "", false, "", `{"ok":true}`, ""},
		{"opencode deny throws", "opencode", "tool.execute.before", "tool_gate", "deny", "", false, "", `{"threw":"no rm here"`, ""},
		{"opencode deny toasts", "opencode", "tool.execute.before", "tool_gate", "deny", "", false, "", `"toasts":[{"body":{"duration":8000,"message":"Tool call blocked: no rm here","title":"SuperBased Observer","variant":"error"}}]`, ""},
		{"opencode ask throws (no native ask)", "opencode", "tool.execute.before", "tool_gate", "ask", "", false, "", `{"threw":"confirm this"`, ""},
		{"opencode flagged allow toasts a warning", "opencode", "tool.execute.before", "tool_gate", "warn", "", false, "", `{"ok":true,"toasts":[{"body":{"duration":6000,"message":"observer: heads up","title":"SuperBased Observer","variant":"warning"}}]}`, ""},
		{"kilo deny throws", "kilo-code-cli", "tool.execute.before", "tool_gate", "deny", "", false, "", `{"threw":"no rm here"`, ""},
		{"garbage, not enforced: allow, recorded fail_open", "opencode", "tool.execute.before", "tool_gate", "garbage", "", false, "", `{"ok":true}`, `"kind":"unparseable","at":`},
		{"garbage, enforced posture: deny", "opencode", "tool.execute.before", "tool_gate", "garbage", enforcedPosture, false, "", `internal error`, `"kind":"unparseable"`},
		{"enforced posture is recorded fail_closed", "opencode", "tool.execute.before", "tool_gate", "garbage", enforcedPosture, false, "", `internal error`, `"outcome":"fail_closed"`},
		// T-050 / review M2-02: a stale enforced posture (the daemon stopped)
		// is ignored, so the failure follows "not enforced".
		{"stale enforced posture is ignored", "opencode", "tool.execute.before", "tool_gate", "garbage", postureAt(time.Now().Add(-10 * time.Minute)), false, "", `{"ok":true}`, `"outcome":"fail_open"`},
		{"future-dated posture is ignored", "opencode", "tool.execute.before", "tool_gate", "garbage", postureAt(time.Now().Add(10 * time.Minute)), false, "", `{"ok":true}`, `"outcome":"fail_open"`},
		{"posture without written_at is ignored", "opencode", "tool.execute.before", "tool_gate", "garbage", `{"schema":1,"enforced":true,"gate_caps":["tool_gate"]}`, false, "", `{"ok":true}`, `"outcome":"fail_open"`},
		{"crash, enforced: deny", "opencode", "tool.execute.before", "tool_gate", "crash", enforcedPosture, false, "", `internal error`, `"kind":"unparseable"`},
		{"missing binary, enforced: deny", "opencode", "tool.execute.before", "tool_gate", "allow", enforcedPosture, true, "", `internal error`, `"kind":"crash"`},
		{"missing binary, not enforced: allow, recorded fail_open", "opencode", "tool.execute.before", "tool_gate", "allow", "", true, "", `{"ok":true}`, `"outcome":"fail_open"`},
		{"timeout, enforced: deny", "opencode", "tool.execute.before", "tool_gate", "hang", enforcedPosture, false, "", `in time`, `"kind":"timeout"`},
		{"timeout, not enforced: allow, recorded fail_open", "opencode", "tool.execute.before", "tool_gate", "hang", "", false, "", `{"ok":true}`, `"outcome":"fail_open"`},
		{"forged schema posture is ignored", "opencode", "tool.execute.before", "tool_gate", "garbage", `{"schema":9,"enforced":true,"gate_caps":["tool_gate"]}`, false, "", `{"ok":true}`, `"outcome":"fail_open"`},
		{"posture for another cap is ignored", "opencode", "tool.execute.before", "tool_gate", "garbage", `{"schema":1,"enforced":true,"gate_caps":["prompt_gate"]}`, false, "", `{"ok":true}`, `"outcome":"fail_open"`},
		// chat.message: a stop THROWS (the host rejects the prompt before
		// it is stored, so the model is never called), paired with a toast.
		{"chat.message allow untouched", "opencode", "chat.message", "prompt_gate", "allow", "", false, "", `"text":"my secret"`, ""},
		{"chat.message allow shows no toast", "opencode", "chat.message", "prompt_gate", "allow", "", false, "", `"threw":null,"toasts":[]`, ""},
		{"chat.message deny throws", "opencode", "chat.message", "prompt_gate", "deny", "", false, "", `"threw":"no rm here"`, ""},
		{"chat.message deny leaves the text alone", "opencode", "chat.message", "prompt_gate", "deny", "", false, "", `"parts":[{"text":"my secret","type":"text"},{"type":"file"},{"text":"tail","type":"text"}]`, ""},
		// The host shows only a generic error for a throw: the reason rides
		// the host's own TUI toast, client.tui.showToast({body}).
		{"chat.message deny toasts the developer", "opencode", "chat.message", "prompt_gate", "deny", "", false, "", `"toasts":[{"body":{"duration":10000,"message":"Your message was not sent: no rm here","title":"SuperBased Observer","variant":"error"}}]`, ""},
		{"chat.message ask throws and toasts a warning", "opencode", "chat.message", "prompt_gate", "ask", "", false, "", `"threw":"confirm this","toasts":[{"body":{"duration":10000,"message":"Your message was not sent: confirm this","title":"SuperBased Observer","variant":"warning"}}]`, ""},
		{"chat.message warn toasts and sends untouched", "opencode", "chat.message", "prompt_gate", "warn", "", false, "", `"threw":null,"toasts":[{"body":{"duration":8000,"message":"observer: heads up","title":"SuperBased Observer","variant":"warning"}}]`, ""},
		{"chat.message warn leaves the text alone", "opencode", "chat.message", "prompt_gate", "warn", "", false, "", `"parts":[{"text":"my secret","type":"text"},{"type":"file"},{"text":"tail","type":"text"}]`, ""},
		{"chat.message modify toasts the developer", "opencode", "chat.message", "prompt_gate", "modify", "", false, "", `"toasts":[{"body":{"duration":5000,"message":"Your message was changed before it reached the model.","title":"SuperBased Observer","variant":"info"}}]`, ""},
		{"chat.message deny with a broken toast client still throws", "opencode", "chat.message", "prompt_gate", "deny", "", false, "", `"broken":{"absent":"threw: no rm here","rejects":"threw: no rm here","throws":"threw: no rm here"}`, ""},
		{"chat.message enforced timeout throws", "opencode", "chat.message", "prompt_gate", "hang", enforcedPosture, false, "", `"threw":"Observer could not evaluate this call in time`, `"kind":"timeout"`},
		{"kilo chat.message deny toasts the developer", "kilo-code-cli", "chat.message", "prompt_gate", "deny", "", false, "", `"message":"Your message was not sent: no rm here"`, ""},
		{"chat.message modify", "opencode", "chat.message", "prompt_gate", "modify", "", false, "", `[{"text":"redacted text","type":"text"},{"type":"file"}]`, ""},
		// pi tool_call: {block, reason}; an ask opens ctx.ui.confirm with a UI.
		{"pi deny", "pi", "tool_call", "tool_gate", "deny", "", false, "", `"ret":{"block":true,"reason":"no rm here"}`, ""},
		{"pi deny notifies with a UI", "pi", "tool_call", "tool_gate", "deny", "", false, "yes", `"notes":[{"level":"error","message":"SuperBased Observer: Tool call blocked: no rm here"}]`, ""},
		{"pi allow", "pi", "tool_call", "tool_gate", "allow", "", false, "", `{"confirms":[],"notes":[],"ret":null}`, ""},
		{"pi timeout enforced", "pi", "tool_call", "tool_gate", "hang", enforcedPosture, false, "", `"block":true`, `"kind":"timeout"`},
		{"pi ask, confirmed in the UI: allowed", "pi", "tool_call", "tool_gate", "ask", "", false, "yes", `{"confirms":[{"message":"confirm this","timeout":1500,"title":"SuperBased Observer: allow this tool call?"}],"notes":[],"ret":null}`, ""},
		{"pi ask, refused in the UI: blocked", "pi", "tool_call", "tool_gate", "ask", "", false, "no", `"ret":{"block":true,"reason":"confirm this"}`, ""},
		{"pi ask, no UI: blocked", "pi", "tool_call", "tool_gate", "ask", "", false, "", `{"confirms":[],"notes":[],"ret":{"block":true,"reason":"confirm this"}}`, ""},
		{"pi flagged allow notifies", "pi", "tool_call", "tool_gate", "warn", "", false, "yes", `{"confirms":[],"notes":[{"level":"warning","message":"SuperBased Observer: observer: heads up"}],"ret":null}`, ""},
		// pi input: handled (no request), confirm, transform, continue.
		{"pi input allow continues", "pi", "input", "prompt_gate", "allow", "", false, "yes", `{"confirms":[],"ext":{"action":"continue"},"notes":[],"ret":{"action":"continue"}}`, ""},
		{"pi input deny is handled and notified", "pi", "input", "prompt_gate", "deny", "", false, "yes", `"notes":[{"level":"error","message":"SuperBased Observer: Your message was not sent: no rm here"}],"ret":{"action":"handled"}`, ""},
		{"pi input deny without a UI is handled", "pi", "input", "prompt_gate", "deny", "", false, "", `"notes":[],"ret":{"action":"handled"}`, ""},
		{"pi input ask, confirmed: continues", "pi", "input", "prompt_gate", "ask", "", false, "yes", `{"confirms":[{"message":"confirm this","timeout":1500,"title":"SuperBased Observer: send this message anyway?"}],"ext":{"action":"continue"},"notes":[],"ret":{"action":"continue"}}`, ""},
		{"pi input ask, refused: handled", "pi", "input", "prompt_gate", "ask", "", false, "no", `"ret":{"action":"handled"}`, ""},
		{"pi input ask, no UI: handled (resend to confirm)", "pi", "input", "prompt_gate", "ask", "", false, "", `{"confirms":[],"ext":{"action":"continue"},"notes":[],"ret":{"action":"handled"}}`, ""},
		{"pi input modify transforms, keeping images", "pi", "input", "prompt_gate", "modify", "", false, "yes", `"ret":{"action":"transform","images":[{"type":"image"}],"text":"redacted text"}`, ""},
		{"pi input warn notifies and continues", "pi", "input", "prompt_gate", "warn", "", false, "yes", `"notes":[{"level":"warning","message":"SuperBased Observer: observer: heads up"}],"ret":{"action":"continue"}`, ""},
		{"pi input timeout enforced: handled", "pi", "input", "prompt_gate", "hang", enforcedPosture, false, "", `"ret":{"action":"handled"}`, `"kind":"timeout"`},
		{"pi input garbage, not enforced: continues", "pi", "input", "prompt_gate", "garbage", "", false, "", `"ret":{"action":"continue"}`, `"outcome":"fail_open"`},
		// OpenClaw: block / requireApproval.
		{"openclaw deny", "openclaw", "before_tool_call", "tool_gate", "deny", "", false, "", `"ret":{"block":true,"blockReason":"no rm here"}`, ""},
		{"openclaw ask = native approval", "openclaw", "before_tool_call", "tool_gate", "ask", "", false, "", `"requireApproval":{"description":"confirm this","severity":"warning","title":"SuperBased Observer guard"}`, ""},
		// Cordis: {kind:"deny"} or next().
		{"cordis deny", "deepseek", "tools/pre-execute", "tool_gate", "deny", "", false, "", `{"ret":{"kind":"deny","reason":"no rm here"}}`, ""},
		{"cordis allow calls next", "deepseek", "tools/pre-execute", "tool_gate", "allow", "", false, "", `{"ret":"NEXT"}`, ""},
		// commandcode Mods.
		{"commandcode beforeToolCall deny", "command-code", "beforeToolCall", "tool_gate", "deny", "", false, "", `{"ret":{"additionalContext":"no rm here","block":true}}`, ""},
		{"commandcode transformInput handled", "command-code", "transformInput", "prompt_gate", "handled", "", false, "", `{"ret":{"action":"handled","message":"cc blocked"}}`, ""},
		{"commandcode transformInput timeout enforced", "command-code", "transformInput", "prompt_gate", "hang", enforcedPosture, false, "", `"action":"handled"`, `"kind":"timeout"`},
		{"commandcode transformInput garbage open", "command-code", "transformInput", "prompt_gate", "garbage", "", false, "", `{"ret":{"action":"continue"}}`, `"outcome":"fail_open"`},
		// T-711: a leftover shim of an INACTIVE adapter. `observer hook` answers
		// the generic {"decision":"approve"} (cmd/observer/hook_components.go,
		// the L2 adapter gate) and records nothing. Every shape reads it as
		// allow, it is an answer (never a failure, so nothing is spooled), and
		// it carries no enforced hint, so it neither opens nor closes anything.
		{"inactive adapter: opencode tool gate allows", "opencode", "tool.execute.before", "tool_gate", "inactive", "", false, "", `{"ok":true}`, ""},
		{"inactive adapter: opencode tool gate allows under an enforced posture", "opencode", "tool.execute.before", "tool_gate", "inactive", enforcedPosture, false, "", `{"ok":true}`, ""},
		{"inactive adapter: kilo tool gate allows", "kilo-code-cli", "tool.execute.before", "tool_gate", "inactive", "", false, "", `{"ok":true}`, ""},
		{"inactive adapter: opencode prompt untouched, no toast", "opencode", "chat.message", "prompt_gate", "inactive", "", false, "", `"toasts":[]`, ""},
		{"inactive adapter: pi allows", "pi", "tool_call", "tool_gate", "inactive", "", false, "", `"ret":null`, ""},
		{"inactive adapter: pi input continues", "pi", "input", "prompt_gate", "inactive", "", false, "", `"ret":{"action":"continue"}`, ""},
		{"inactive adapter: openclaw allows", "openclaw", "before_tool_call", "tool_gate", "inactive", "", false, "", `"ret":null`, ""},
		{"inactive adapter: cordis calls next", "deepseek", "tools/pre-execute", "tool_gate", "inactive", "", false, "", `{"ret":"NEXT"}`, ""},
		{"inactive adapter: commandcode beforeToolCall allows", "command-code", "beforeToolCall", "tool_gate", "inactive", "", false, "", `{"ret":null}`, ""},
		{"inactive adapter: commandcode transformInput continues", "command-code", "transformInput", "prompt_gate", "inactive", "", false, "", `{"ret":{"action":"continue"}}`, ""},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			r := runShim(t, node, c.tool, c.event, c.cap, c.mode, c.posture, 1500, c.missing, "FAKE_UI="+c.ui)
			got := jsonOf(r.out)
			if !strings.Contains(got, c.want) {
				t.Fatalf("output %s; want substring %s", got, c.want)
			}
			if c.spool == "" && r.spool != "" {
				t.Fatalf("unexpected spool %q", r.spool)
			}
			if c.spool != "" && !strings.Contains(r.spool, c.spool) {
				t.Fatalf("spool %q; want %s", r.spool, c.spool)
			}
			if !c.missing {
				if !strings.Contains(r.argv, "hook "+c.tool+" "+c.event+" --max-runtime 1200ms --config /cfg/config.toml") {
					t.Fatalf("argv %q", r.argv)
				}
			}
		})
	}
}

// TestShimEnvelope pins the JSON the shim sends for a gate event.
func TestShimEnvelope(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake observer is a POSIX shell script")
	}
	node := shimNode(t)
	r := runShim(t, node, "opencode", "tool.execute.before", "tool_gate", "allow", "", 3000, false)
	var env map[string]any
	if err := json.Unmarshal([]byte(r.stdin), &env); err != nil {
		t.Fatalf("stdin %q: %v", r.stdin, err)
	}
	if env["host"] != "opencode" || env["event"] != "tool.execute.before" || env["session_id"] != "s1" ||
		env["cwd"] != "/w" || env["tool_name"] != "bash" || env["call_id"] != "c1" {
		t.Fatalf("envelope = %v", env)
	}
	if in, _ := env["tool_input"].(map[string]any); in["command"] != "rm -rf ~/x" {
		t.Fatalf("tool_input = %v", env["tool_input"])
	}
	if pid, _ := env["pid"].(float64); pid <= 1 {
		t.Fatalf("pid = %v", env["pid"])
	}
}

// TestShimEnforcedHintOutlivesPosture: an observer reply's enforced hint
// decides a later failure (it was verified by observer), even with no
// posture file.
func TestShimEnforcedHintOutlivesPosture(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX only")
	}
	node := shimNode(t)
	dir := t.TempDir()
	fake := filepath.Join(dir, "observer")
	script := "#!/bin/sh\ncat >/dev/null\nif [ -f \"$FAKE_DIR/once\" ]; then echo garbage; else touch \"$FAKE_DIR/once\"; echo '{\"decision\":\"allow\",\"enforced\":true}'; fi\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	h, _ := HostFor("pi")
	shim, _ := Render(h, RenderOptions{Events: map[string]string{"tool_call": "tool_gate"}, Bin: fake, SpoolPath: filepath.Join(dir, "spool")})
	_ = os.WriteFile(filepath.Join(dir, "shim.mjs"), shim, 0o600)
	drv := `const E=(await import(process.argv[2])).default;const h={};E({on:(n,f)=>{h[n]=f}});
const a=await h.tool_call({toolName:"bash",input:{command:"ls"}},{cwd:"/w"});
const b=await h.tool_call({toolName:"bash",input:{command:"ls"}},{cwd:"/w"});
console.log(JSON.stringify({a:a??null,b:b??null}));`
	_ = os.WriteFile(filepath.Join(dir, "d.mjs"), []byte(drv), 0o600)
	cmd := exec.Command(node, filepath.Join(dir, "d.mjs"), filepath.Join(dir, "shim.mjs"))
	cmd.Env = append(os.Environ(), "FAKE_DIR="+dir, "OBSERVER_BIN=")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if !strings.Contains(string(out), `{"a":null,"b":{"block":true`) {
		t.Fatalf("out = %s", out)
	}
}

// runTwoCalls renders a pi shim whose fake observer answers the first call
// with firstReply and the second with garbage, with posture (may be "") and
// configFile (may be "") baked in, and returns both outcomes plus the spool.
func runTwoCalls(t *testing.T, node, firstReply, posture string, configMtime time.Time) (string, string) {
	t.Helper()
	dir := t.TempDir()
	fake := filepath.Join(dir, "observer")
	script := "#!/bin/sh\ncat >/dev/null\nif [ -f \"$FAKE_DIR/once\" ]; then echo garbage; else touch \"$FAKE_DIR/once\"; echo '" + firstReply + "'; fi\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	posturePath := filepath.Join(dir, "guard-posture.json")
	if posture != "" {
		if err := os.WriteFile(posturePath, []byte(posture), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := ""
	if !configMtime.IsZero() {
		cfg = filepath.Join(dir, "config.toml")
		if err := os.WriteFile(cfg, []byte("[guard]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(cfg, configMtime, configMtime); err != nil {
			t.Fatal(err)
		}
	}
	spool := filepath.Join(dir, "spool")
	h, _ := HostFor("pi")
	shim, _ := Render(h, RenderOptions{
		Events: map[string]string{"tool_call": "tool_gate"}, Bin: fake,
		PosturePath: posturePath, PostureSchema: 1, SpoolPath: spool, ConfigFile: cfg,
	})
	_ = os.WriteFile(filepath.Join(dir, "shim.mjs"), shim, 0o600)
	drv := `const E=(await import(process.argv[2])).default;const h={};E({on:(n,f)=>{h[n]=f}});
const a=await h.tool_call({toolName:"bash",input:{command:"ls"}},{cwd:"/w"});
const b=await h.tool_call({toolName:"bash",input:{command:"ls"}},{cwd:"/w"});
console.log(JSON.stringify({a:a??null,b:b??null}));`
	_ = os.WriteFile(filepath.Join(dir, "d.mjs"), []byte(drv), 0o600)
	cmd := exec.Command(node, filepath.Join(dir, "d.mjs"), filepath.Join(dir, "shim.mjs"))
	cmd.Env = append(os.Environ(), "FAKE_DIR="+dir, "OBSERVER_BIN=")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	sp, _ := os.ReadFile(spool)
	return string(out), string(sp)
}

// TestShimHintOnlyTightens pins review M2-04: an `enforced: false` hint from
// a recent reply never opens a failure a fresh enforced posture closes.
func TestShimHintOnlyTightens(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX only")
	}
	node := shimNode(t)
	out, sp := runTwoCalls(t, node, `{"decision":"allow","enforced":false}`, postureAt(time.Now()), time.Time{})
	if !strings.Contains(out, `{"a":null,"b":{"block":true`) {
		t.Fatalf("an enforced:false hint opened a failure the fresh posture closes: %s", out)
	}
	if !strings.Contains(sp, `"outcome":"fail_closed"`) {
		t.Fatalf("spool = %q", sp)
	}
}

// TestShimPostureOlderThanConfigIsStale pins the config half of T-050 in the
// shim (review M2-02): a posture written before config.toml last changed is
// ignored, exactly as the Go hook ignores it.
func TestShimPostureOlderThanConfigIsStale(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX only")
	}
	node := shimNode(t)
	written := time.Now().Add(-30 * time.Second)
	out, sp := runTwoCalls(t, node, `{"decision":"allow"}`, postureAt(written), written.Add(10*time.Second))
	if !strings.Contains(out, `{"a":null,"b":null}`) || !strings.Contains(sp, `"outcome":"fail_open"`) {
		t.Fatalf("a posture older than config.toml still closed the failure: %s (spool %q)", out, sp)
	}
	// The same posture with the config unchanged since: closed.
	out, _ = runTwoCalls(t, node, `{"decision":"allow"}`, postureAt(written), written.Add(-time.Minute))
	if !strings.Contains(out, `"b":{"block":true`) {
		t.Fatalf("a fresh posture newer than config.toml did not close: %s", out)
	}
}

// TestShimInertLoad: an inert profile (no events) loads under every shape
// and registers nothing, and an unknown shape still yields a loadable
// OpenCode-safe entry.
func TestShimInertLoad(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX only")
	}
	node := shimNode(t)
	for _, shape := range []string{ShapeOpenCode, ShapePi, ShapeOpenClaw, ShapeCordis, ShapeCommandCode, "nope"} {
		dir := t.TempDir()
		shim, err := Render(Host{Tool: "x", Shape: shape}, RenderOptions{})
		if err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(filepath.Join(dir, "shim.mjs"), shim, 0o600)
		drv := `const E=(await import(process.argv[2])).default;let n=0;const api={on:()=>{n++},hooks:(h)=>{n+=Object.keys(h).length}};
if(typeof E==="function")E(api);else if(E.server){const h=await E.server({});n+=Object.keys(h).length}else if(E.register)E.register(api);else if(E.apply)E.apply(api);
console.log(n)`
		_ = os.WriteFile(filepath.Join(dir, "d.mjs"), []byte(drv), 0o600)
		out, err := exec.Command(node, filepath.Join(dir, "d.mjs"), filepath.Join(dir, "shim.mjs")).CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != "0" {
			t.Fatalf("shape %s: %v %s", shape, err, out)
		}
	}
}

// TestShimPinsPaths: with PinPaths (a managed node) the shim runs the
// baked-in binary and config even when the host's environment names
// another OBSERVER_BIN and OBSERVER_CONFIG; without it the environment
// still wins (security pillar plan section 5.1 item 6).
func TestShimPinsPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell for the fake observer")
	}
	node := shimNode(t)
	for _, pin := range []bool{true, false} {
		dir := t.TempDir()
		fake := filepath.Join(dir, "observer")
		if err := os.WriteFile(fake, []byte(fakeObserver), 0o755); err != nil {
			t.Fatal(err)
		}
		h, _ := HostFor("opencode")
		shim, err := Render(h, RenderOptions{Events: map[string]string{"tool.execute.before": "tool_gate"}, Bin: fake, Config: "/cfg/config.toml", PinPaths: pin, PostureSchema: 1})
		if err != nil {
			t.Fatal(err)
		}
		if profileOf(t, shim).PinPaths != pin {
			t.Fatalf("pin_paths not baked as %v", pin)
		}
		shimPath, drvPath := filepath.Join(dir, "shim.mjs"), filepath.Join(dir, "driver.mjs")
		if err := os.WriteFile(shimPath, shim, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(drvPath, []byte(driver), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(node, drvPath, shimPath, h.Shape, "tool.execute.before")
		cmd.Env = append(os.Environ(), "FAKE_MODE=allow", "FAKE_DIR="+dir,
			"OBSERVER_BIN="+filepath.Join(dir, "planted-observer"), "OBSERVER_CONFIG=/planted/config.toml")
		if raw, err := cmd.Output(); err != nil {
			t.Fatalf("node driver: %v (%s)", err, raw)
		}
		argv, _ := os.ReadFile(filepath.Join(dir, "argv"))
		ran := strings.Contains(string(argv), "--config /cfg/config.toml")
		if ran != pin {
			t.Fatalf("pin %v: baked observer ran = %v (argv %q)", pin, ran, argv)
		}
	}
}
