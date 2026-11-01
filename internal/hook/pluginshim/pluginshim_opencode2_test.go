package pluginshim

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// TestOpenCodeV2ShimUnderNode runs the OpenCode shape through its v2
// contract (setup(context), OpenCode 2.x, FU-121) under a real Node with the
// fake observer: the same decisions and the same fail-closed rules as the v1
// cases in TestShimUnderNode, reached through context.tool.hook and
// context.session.hook.
func TestOpenCodeV2ShimUnderNode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake observer is a POSIX shell script")
	}
	node := shimNode(t)
	cases := []struct {
		name, tool, event, cap, mode, posture string
		missing                               bool
		want, spool                           string
	}{
		{"tool allow", "opencode", "tool.execute.before", "tool_gate", "allow", "", false, `{"hooks":["tool.execute.before"],"ok":true}`, ""},
		{"tool deny throws", "opencode", "tool.execute.before", "tool_gate", "deny", "", false, `"threw":"no rm here"`, ""},
		{"tool ask throws (no native ask)", "opencode", "tool.execute.before", "tool_gate", "ask", "", false, `"threw":"confirm this"`, ""},
		{"tool flagged allow passes", "opencode", "tool.execute.before", "tool_gate", "warn", "", false, `"ok":true`, ""},
		{"tool garbage, not enforced: allow, recorded fail_open", "opencode", "tool.execute.before", "tool_gate", "garbage", "", false, `"ok":true`, `"outcome":"fail_open"`},
		{"tool garbage, enforced: deny", "opencode", "tool.execute.before", "tool_gate", "garbage", enforcedPosture, false, `internal error`, `"outcome":"fail_closed"`},
		{"tool missing binary, enforced: deny", "opencode", "tool.execute.before", "tool_gate", "allow", enforcedPosture, true, `internal error`, `"kind":"crash"`},
		{"tool timeout, enforced: deny", "opencode", "tool.execute.before", "tool_gate", "hang", enforcedPosture, false, `in time`, `"kind":"timeout"`},
		{"tool timeout, not enforced: allow", "opencode", "tool.execute.before", "tool_gate", "hang", "", false, `"ok":true`, `"outcome":"fail_open"`},
		{"tool inactive adapter allows under enforcement", "opencode", "tool.execute.before", "tool_gate", "inactive", enforcedPosture, false, `"ok":true`, ""},
		{"kilo tool deny throws through v2 too", "kilo-code-cli", "tool.execute.before", "tool_gate", "deny", "", false, `"threw":"no rm here"`, ""},
		{"prompt allow untouched", "opencode", "chat.message", "prompt_gate", "allow", "", false, `"prompt":{"files":[],"text":"my secret"},"threw":null`, ""},
		{"prompt deny throws, text untouched", "opencode", "chat.message", "prompt_gate", "deny", "", false, `"prompt":{"files":[],"text":"my secret"},"threw":"no rm here"`, ""},
		{"prompt ask throws", "opencode", "chat.message", "prompt_gate", "ask", "", false, `"threw":"confirm this"`, ""},
		{"prompt modify rewrites the text", "opencode", "chat.message", "prompt_gate", "modify", "", false, `"prompt":{"files":[],"text":"redacted text"},"threw":null`, ""},
		{"prompt timeout, enforced: throws", "opencode", "chat.message", "prompt_gate", "hang", enforcedPosture, false, `"threw":"Observer could not evaluate this call in time`, `"kind":"timeout"`},
		{"prompt hook name", "opencode", "chat.message", "prompt_gate", "allow", "", false, `"hooks":["session.prompt"]`, ""},
		{"post-tool feedback appends to the output", "opencode", "tool.execute.after", "context_inject", "context", "", false, `{"hooks":["tool.execute.after"],"output":"out\n\nguard: check the diff"}`, ""},
		{"post-tool failure leaves the output", "opencode", "tool.execute.after", "context_inject", "garbage", "", false, `"output":"out"`, ""},
		{"bus event subscribes", "opencode", "session.idle", "session_end", "allow", "", false, `{"hooks":[],"subs":1}`, ""},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			r := runShim(t, node, c.tool, c.event, c.cap, c.mode, c.posture, 1500, c.missing, "FAKE_CONTRACT=v2")
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
			if !c.missing && !strings.Contains(r.argv, "hook "+c.tool+" "+c.event+" --max-runtime") {
				t.Fatalf("argv %q", r.argv)
			}
		})
	}
}

// TestOpenCodeV2ShimEnvelope pins the JSON a v2 tool gate sends: the v1
// event name and field names, read from the v2 hook payload.
func TestOpenCodeV2ShimEnvelope(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake observer is a POSIX shell script")
	}
	node := shimNode(t)
	r := runShim(t, node, "opencode", "tool.execute.before", "tool_gate", "allow", "", 3000, false, "FAKE_CONTRACT=v2")
	for _, want := range []string{`"host":"opencode"`, `"event":"tool.execute.before"`, `"session_id":"s1"`, `"cwd":"/w"`, `"tool_name":"bash"`, `"call_id":"c1"`, `"tool_input":{"command":"rm -rf ~/x"}`} {
		if !strings.Contains(r.stdin, want) {
			t.Fatalf("stdin %s; want %s", r.stdin, want)
		}
	}
}

// loaderChecks replays both OpenCode loaders' checks on a rendered shim's
// default export, transcribed from the host binaries:
//   - v1 (opencode 1.19.5, the Mv() check): the default export is an object,
//     server (when present) is a function, tui (when present) is a function,
//     not both server and tui, and a server plugin has server.
//   - v2 (@opencode-ai/cli 0.0.0-beta-19271, the PluginModule.load schema
//     behind "Plugin must export a default definition with an id and an
//     effect or setup function"): default is {id: string, effect: function}
//     or {id: string, setup: function}; extra keys are ignored.
//
// It then runs setup with an empty context (a host offering none of the
// domains) and with a context whose hook registration throws: neither may
// reject.
const loaderChecks = `
const [shimPath] = process.argv.slice(2);
const mod = await import(shimPath);
const e = mod.default;
const out = {};
const isObj = (v) => v !== null && typeof v === "object";
out.v1 = isObj(e) && (!("server" in e) || typeof e.server === "function") && (!("tui" in e) || typeof e.tui === "function") && !("server" in e && "tui" in e) && typeof e.server === "function";
out.v2 = isObj(e) && typeof e.id === "string" && (typeof e.effect === "function" || typeof e.setup === "function");
out.namedExports = Object.keys(mod).filter((k) => k !== "default");
try { await e.setup({}); out.emptyContext = "ok"; } catch (err) { out.emptyContext = String(err); }
const boom = { hook: async () => { throw new Error("no such hook"); } };
try { await e.setup({ tool: boom, session: boom, event: { subscribe: async () => { throw new Error("x"); } } }); out.throwingContext = "ok"; } catch (err) { out.throwingContext = String(err); }
console.log(JSON.stringify(out));
`

// TestOpenCodeShimSatisfiesBothLoaders: one rendered OpenCode shim (and the
// Kilo CLI one, which shares the shape) passes the v1 and the v2 loader
// checks, with every event subscribed and with none (the inert render), and
// setup never rejects (FU-121).
func TestOpenCodeShimSatisfiesBothLoaders(t *testing.T) {
	node := shimNode(t)
	all := map[string]string{"tool.execute.before": "tool_gate", "chat.message": "prompt_gate", PostToolEvent: "context_inject", "session.idle": "session_end"}
	for _, tool := range []string{"opencode", "kilo-code-cli"} {
		for name, ev := range map[string]map[string]string{"all events": all, "inert": {}} {
			t.Run(tool+" "+name, func(t *testing.T) {
				h, _ := HostFor(tool)
				shim, err := Render(h, RenderOptions{Events: ev, Bin: "/no/such/observer"})
				if err != nil {
					t.Fatal(err)
				}
				dir := t.TempDir()
				shimPath := filepath.Join(dir, "shim.mjs")
				drv := filepath.Join(dir, "loader.mjs")
				if err := os.WriteFile(shimPath, shim, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(drv, []byte(loaderChecks), 0o600); err != nil {
					t.Fatal(err)
				}
				raw, err := exec.Command(node, drv, shimPath).Output()
				if err != nil {
					t.Fatalf("node: %v (%s)", err, raw)
				}
				want := `{"v1":true,"v2":true,"namedExports":[],"emptyContext":"ok","throwingContext":"ok"}`
				if got := strings.TrimSpace(string(raw)); got != want {
					t.Fatalf("loader checks = %s; want %s", got, want)
				}
			})
		}
	}
}

// TestOpenCodeV2ShimRecordsAFailedRegistration: a v2 host whose hook
// registration throws, rejects, resolves to a value without dispose (a lazy
// Effect the host never ran) or lacks the domain leaves a gate unhooked;
// the shim spools that like any gate failure (fail_open, or fail_closed
// under a fresh enforced posture) and names it once on stderr. A non-gate
// event's failed registration records nothing.
func TestOpenCodeV2ShimRecordsAFailedRegistration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake observer is a POSIX shell script")
	}
	node := shimNode(t)
	for _, fail := range []string{"throw", "reject", "lazy", "nodomain"} {
		for _, c := range []struct {
			event, cap, posture, outcome string
		}{
			{"tool.execute.before", "tool_gate", "", "fail_open"},
			{"tool.execute.before", "tool_gate", enforcedPosture, "fail_closed"},
			{"chat.message", "prompt_gate", "", "fail_open"},
			{"chat.message", "prompt_gate", enforcedPosture, "fail_closed"},
			{PostToolEvent, "context_inject", "", ""},
		} {
			name := fail + "/" + c.event + "/" + c.outcome
			t.Run(name, func(t *testing.T) {
				r := runShim(t, node, "opencode", c.event, c.cap, "allow", c.posture, 1500, false, "FAKE_CONTRACT=v2", "FAKE_V2_HOOK="+fail)
				if hooks, _ := r.out["hooks"].([]any); len(hooks) != 0 {
					t.Fatalf("hooks registered on a failing host: %v", hooks)
				}
				errs, _ := r.out["errs"].([]any)
				if c.outcome == "" {
					if r.spool != "" || len(errs) != 0 {
						t.Fatalf("a non-gate event recorded a failure: spool %q, errs %v", r.spool, errs)
					}
					return
				}
				for _, want := range []string{`"event":"` + c.event + `"`, `"cap":"` + c.cap + `"`, `"kind":"register"`, `"outcome":"` + c.outcome + `"`} {
					if !strings.Contains(r.spool, want) {
						t.Fatalf("spool %q; want %s", r.spool, want)
					}
				}
				if strings.Count(r.spool, "\n") != 1 {
					t.Fatalf("spool %q: want one record", r.spool)
				}
				if len(errs) != 1 || !strings.Contains(errs[0].(string), c.event) {
					t.Fatalf("errs %v: want one line naming %s", errs, c.event)
				}
				if r.argv != "" {
					t.Fatalf("observer ran on a failed registration: %q", r.argv)
				}
			})
		}
	}
}

// TestOpenCodeV2ShimReadsArgsToo: a v2 payload naming the tool input "args"
// instead of "input" still reaches observer as tool_input.
func TestOpenCodeV2ShimReadsArgsToo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake observer is a POSIX shell script")
	}
	node := shimNode(t)
	r := runShim(t, node, "opencode", "tool.execute.before", "tool_gate", "allow", "", 3000, false, "FAKE_CONTRACT=v2", "FAKE_V2_ARGS=1")
	if !strings.Contains(r.stdin, `"tool_input":{"command":"rm -rf ~/x"}`) {
		t.Fatalf("stdin %s", r.stdin)
	}
}

// TestOpenCodeV1HostCallingSetupTakesOnePath (FU-188): Kilo CLI 7.8.x is a
// v1 host that also calls setup, with its v1 input. The shim takes exactly
// one path: server's hooks gate the call, the v2 setup registers nothing,
// prints nothing and writes no register record, in either call order.
func TestOpenCodeV1HostCallingSetupTakesOnePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake observer is a POSIX shell script")
	}
	node := shimNode(t)
	for _, order := range []string{"setup-first", "server-first"} {
		for _, posture := range []string{"", enforcedPosture} {
			t.Run(order+"/enforced="+strconv.FormatBool(posture != ""), func(t *testing.T) {
				r := runShim(t, node, "kilo-code-cli", "tool.execute.before", "tool_gate", "deny", posture, 1500, false, "FAKE_CONTRACT=v1both", "FAKE_ORDER="+order)
				got := jsonOf(r.out)
				if !strings.Contains(got, `"hooks":["tool.execute.before"]`) || !strings.Contains(got, `"threw":"no rm here"`) {
					t.Fatalf("output %s; want server's tool gate blocking", got)
				}
				if errs, _ := r.out["errs"].([]any); len(errs) != 0 {
					t.Fatalf("setup printed %v on a v1 host", errs)
				}
				if strings.Contains(r.spool, `"kind":"register"`) {
					t.Fatalf("spool %q: a register record on a v1 host", r.spool)
				}
				if n := strings.Count(r.argv, "hook kilo-code-cli tool.execute.before"); n != 1 {
					t.Fatalf("argv %q: the gate ran %d times, want once", r.argv, n)
				}
			})
		}
	}
}
