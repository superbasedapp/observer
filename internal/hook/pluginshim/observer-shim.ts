// SuperBased Observer plugin shim: one file for every in-process plugin host.
//
// Rendered per host by internal/hook/pluginshim (go:embed): the PROFILE
// literal below is the only part that differs between hosts. It names the
// host's plugin contract ("shape"), the native events this install
// subscribes to (each mapped to the abstract hook capability it provides),
// and the deadlines. Every subscribed event is forwarded as JSON on stdin to
// `observer hook <tool> <event>`; the reply ({"decision": ...}) is mapped
// onto the host's own contract (throw, a returned object, a mutated output).
//
// Written as plain JavaScript (no type annotations) so the same bytes load
// under Bun (OpenCode, Kilo CLI), jiti (pi, commandcode), Node (OpenClaw)
// and Cordis (DeepSeek Harness) without a compile step, and so the tests can
// run it under plain Node.
//
// Failure semantics (hook-parity audit section 5.7):
//   - observer answers inside the deadline: its decision stands. observer
//     applies the fail-closed rule itself (its watchdog runs below this
//     shim's deadline, `--max-runtime`), so a slow evaluation under
//     enforcement already comes back as a deny with a reason.
//   - observer does not answer at all (binary missing, hung, killed at this
//     shim's own deadline, unparseable output): a GATE event is denied with
//     a reason when guard enforcement is in force, and allowed otherwise.
//     "In force" is read only to TIGHTEN, never to open: a recent observer
//     reply's `enforced: true` hint, or the daemon's guard-posture.json
//     while it is FRESH (written within the posture window, not dated in the
//     future, not older than config.toml: the T-050 rule the Go hook
//     applies). A stale posture is ignored, so a stopped daemon cannot keep
//     failures closed forever, and an `enforced: false` hint never opens a
//     failure the posture would close. Either way the failure is appended to
//     guard-hookfail.jsonl for the daemon with its outcome (fail_closed or
//     fail_open, T-049). Observe events never wait and never block.
//   - nothing at module load can throw: the host keeps working when this
//     shim cannot run.

import { spawn, spawnSync } from "node:child_process";
import { readFileSync, appendFileSync, statSync } from "node:fs";

const PROFILE = {{OBSERVER_SHIM_PROFILE}};

const FAIL_TIMEOUT =
  "Observer could not evaluate this call in time; it is blocked because guard enforcement is on. Retry, or ask your admin if this repeats.";
const FAIL_ERROR =
  "Observer could not evaluate this call because of an internal error; it is blocked because guard enforcement is on. Retry, or ask your admin if this repeats.";
const BLOCKED = "Blocked by the SuperBased Observer guard.";
const MAX_OUT = 1 << 20;
const HINT_TTL_MS = 10 * 60 * 1000;
const FIELD_CAP = 256;

// A managed node pins both paths (pin_paths): an inherited OBSERVER_BIN or
// OBSERVER_CONFIG must not point the host at another binary or config.
const BIN = (PROFILE.pin_paths ? "" : process.env.OBSERVER_BIN) || PROFILE.bin || "observer";
const CONFIG = (PROFILE.pin_paths ? "" : process.env.OBSERVER_CONFIG) || PROFILE.config || "";

// enforced hint per capability, from the most recent observer reply.
const hints = {};

function has(event) {
  return Object.prototype.hasOwnProperty.call(PROFILE.events, event);
}

function capOf(event) {
  return PROFILE.events[event] || "";
}

function str(v) {
  return typeof v === "string" ? v : "";
}

function pick(obj, keys) {
  if (!obj || typeof obj !== "object") return undefined;
  for (const k of keys) {
    if (obj[k] !== undefined && obj[k] !== null && obj[k] !== "") return obj[k];
  }
  return undefined;
}

function argvFor(event, deadlineMs) {
  const args = ["hook", PROFILE.tool, event];
  if (deadlineMs > 0) args.push("--max-runtime", Math.max(300, deadlineMs - PROFILE.margin_ms) + "ms");
  if (CONFIG) args.push("--config", CONFIG);
  if (process.platform === "win32" && PROFILE.wsl_bin) {
    return { bin: "wsl.exe", args: ["-d", PROFILE.wsl_distro, "--", PROFILE.wsl_bin, ...args] };
  }
  return { bin: BIN, args };
}

function parseReply(out) {
  const lines = String(out || "").split(/\r?\n/);
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i].trim();
    if (!line) continue;
    try {
      const v = JSON.parse(line);
      if (v && typeof v === "object" && !Array.isArray(v)) return v;
    } catch (_e) {
      // not JSON: keep looking upwards
    }
  }
  return null;
}

function run(event, payload, deadlineMs) {
  return new Promise((resolve) => {
    let done = false;
    let out = "";
    let timer = null;
    const finish = (r) => {
      if (done) return;
      done = true;
      if (timer) clearTimeout(timer);
      resolve(r);
    };
    let child;
    try {
      const { bin, args } = argvFor(event, deadlineMs);
      child = spawn(bin, args, { stdio: ["pipe", "pipe", "ignore"], windowsHide: true });
    } catch (_e) {
      finish({ kind: "crash" });
      return;
    }
    timer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch (_e) {
        // already gone
      }
      finish({ kind: "timeout" });
    }, deadlineMs);
    child.on("error", () => finish({ kind: "crash" }));
    if (child.stdout) {
      child.stdout.on("data", (d) => {
        if (out.length < MAX_OUT) out += d;
      });
    }
    child.on("close", () => {
      const reply = parseReply(out);
      finish(reply ? { reply } : { kind: "unparseable" });
    });
    if (child.stdin) {
      child.stdin.on("error", () => {});
      try {
        child.stdin.end(JSON.stringify(payload));
      } catch (_e) {
        // the close handler reports what happened
      }
    }
  });
}

function runSync(event, payload, deadlineMs) {
  try {
    const { bin, args } = argvFor(event, deadlineMs);
    const r = spawnSync(bin, args, {
      input: JSON.stringify(payload),
      timeout: deadlineMs,
      killSignal: "SIGKILL",
      encoding: "utf8",
      maxBuffer: MAX_OUT,
      windowsHide: true,
    });
    if (r.error) return { kind: r.error.code === "ETIMEDOUT" ? "timeout" : "crash" };
    if (r.signal) return { kind: "timeout" };
    const reply = parseReply(r.stdout);
    return reply ? { reply } : { kind: "unparseable" };
  } catch (_e) {
    return { kind: "crash" };
  }
}

// postureFresh applies the T-050 freshness rule to a posture: written within
// PROFILE.posture_max_age_ms, not more than PROFILE.posture_skew_ms in the
// future, and not older than the config file it was derived from.
function postureFresh(p) {
  // RFC 3339 with up to nanosecond fractions: keep milliseconds for Date.
  const at = Date.parse(str(p.written_at).replace(/(\.\d{3})\d+/, "$1"));
  if (!Number.isFinite(at)) return false;
  const now = Date.now();
  if (now - at > PROFILE.posture_max_age_ms || at - now > PROFILE.posture_skew_ms) return false;
  if (PROFILE.config_file) {
    try {
      if (statSync(PROFILE.config_file).mtimeMs > at) return false;
    } catch (_e) {
      // no config file: nothing changed after the posture was written
    }
  }
  return true;
}

function postureClosed(cap) {
  if (!PROFILE.posture) return false;
  try {
    const p = JSON.parse(readFileSync(PROFILE.posture, "utf8"));
    return (
      !!p &&
      p.schema === PROFILE.posture_schema &&
      p.enforced === true &&
      Array.isArray(p.gate_caps) &&
      p.gate_caps.includes(cap) &&
      postureFresh(p)
    );
  } catch (_e) {
    return false;
  }
}

// failsClosed only ever TIGHTENS: a recent enforced:true hint closes, and so
// does a fresh posture; an enforced:false hint opens nothing.
function failsClosed(cap) {
  const h = hints[cap];
  if (h && h.enforced && Date.now() - h.at < HINT_TTL_MS) return true;
  return postureClosed(cap);
}

function isGate(cap) {
  return cap === "tool_gate" || cap === "prompt_gate";
}

function clip(s) {
  s = str(s);
  return s.length > FIELD_CAP ? s.slice(0, FIELD_CAP) : s;
}

function spool(event, cap, sessionId, kind, outcome) {
  if (!PROFILE.spool) return;
  try {
    const line = JSON.stringify({
      tool: clip(PROFILE.tool),
      event: clip(event),
      cap: clip(cap),
      session_id: clip(sessionId),
      kind: clip(kind),
      at: new Date().toISOString(),
      outcome,
    });
    appendFileSync(PROFILE.spool, line + "\n", { mode: 0o600 });
  } catch (_e) {
    // best effort: the answer already went out
  }
}

// verdictOf normalizes a reply. message is a notice for the developer on an
// allow or a modify (a guard warning or a flagged call): shown, never a
// stop.
function verdictOf(reply) {
  const d = str(reply.decision).toLowerCase();
  if (d === "deny" || d === "block") return { decision: "deny", reason: str(reply.reason) || BLOCKED };
  if (d === "ask") return { decision: "ask", reason: str(reply.reason) || BLOCKED };
  if (d === "modify") return { decision: "modify", prompt: reply.prompt, reason: str(reply.reason), message: str(reply.message) };
  return { decision: "allow", message: str(reply.message) };
}

// failed answers a gate event observer could not: closed under enforcement,
// open otherwise, and recorded either way (T-049: a fail-open failure is a
// guard event too).
function failed(event, cap, sessionId, kind) {
  if (!isGate(cap)) return { decision: "allow" };
  if (failsClosed(cap)) {
    spool(event, cap, sessionId, kind, "fail_closed");
    return { decision: "deny", reason: kind === "timeout" ? FAIL_TIMEOUT : FAIL_ERROR };
  }
  spool(event, cap, sessionId, kind, "fail_open");
  return { decision: "allow" };
}

function settle(event, cap, sessionId, r) {
  if (r.reply) {
    if (typeof r.reply.enforced === "boolean") hints[cap] = { enforced: r.reply.enforced, at: Date.now() };
    return verdictOf(r.reply);
  }
  return failed(event, cap, sessionId, r.kind);
}

async function gate(event, payload) {
  const cap = capOf(event);
  try {
    return settle(event, cap, payload.session_id, await run(event, payload, PROFILE.gate_ms));
  } catch (_e) {
    return failed(event, cap, payload.session_id, "crash");
  }
}

function gateSync(event, payload) {
  const cap = capOf(event);
  try {
    return settle(event, cap, payload.session_id, runSync(event, payload, PROFILE.gate_ms));
  } catch (_e) {
    return failed(event, cap, payload.session_id, "crash");
  }
}

function observe(event, payload) {
  try {
    const { bin, args } = argvFor(event, PROFILE.observe_ms);
    const child = spawn(bin, args, { stdio: ["pipe", "ignore", "ignore"], windowsHide: true });
    child.on("error", () => {});
    const timer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch (_e) {
        // already gone
      }
    }, PROFILE.observe_ms);
    if (timer.unref) timer.unref();
    child.on("close", () => clearTimeout(timer));
    if (child.unref) child.unref();
    if (child.stdin) {
      child.stdin.on("error", () => {});
      child.stdin.end(JSON.stringify(payload));
    }
  } catch (_e) {
    // observe events never affect the host
  }
}

function envelope(event, sessionId, cwd, extra) {
  return Object.assign(
    { host: PROFILE.host, event, session_id: str(sessionId), cwd: str(cwd) || process.cwd(), pid: process.pid },
    extra,
  );
}

function blocks(v) {
  return v.decision === "deny" || v.decision === "ask";
}

// --- OpenCode and Kilo CLI: {id, server} and {id, setup} plugin module -----

// toast tells the DEVELOPER what Observer did: the host's own TUI toast
// through the plugin input's SDK client, client.tui.showToast({body: {title,
// message, variant, duration}}) (POST /tui/show-toast). Grounded in
// @opencode-ai/sdk 1.18.31 (the plugin's v1 createOpencodeClient) and the
// Kilo CLI 7.8.3 binary, which carries the same call. A thrown hook shows the
// developer only a generic server error, so every stop is paired with one.
// Fire-and-forget: never awaited, never throws, a missing client or a
// headless run (`opencode run`, no TUI) shows nothing. The v2 contract hands
// the plugin no TUI client, so a v2 stop carries its reason in the thrown
// error only.
function toast(client, message, variant, duration) {
  try {
    const tui = client && client.tui;
    if (!tui || typeof tui.showToast !== "function") return;
    const p = tui.showToast({ body: { title: "SuperBased Observer", message, variant, duration } });
    if (p && typeof p.catch === "function") p.catch(() => {});
  } catch (_) {
    // a broken client never breaks the hook
  }
}

// opencodeHandlers holds the decision mapping both OpenCode plugin contracts
// wire, over plain values, so the v1 hooks object and the v2 context hooks
// share one code path and one set of fail-closed rules (gate / failed). The
// native event names sent to `observer hook` are the v1 names in either
// contract, so PROFILE.events and the hook receiver are unchanged.
//   toolBefore(sid, tool, args, callID): throws to block (deny, or ask: no
//     native ask), toasts a flagged allow.
//   prompt(sid, text): throws to stop the message (an ask too: the developer
//     resends to confirm, the reconsider-once flow keyed by the session id);
//     returns the replacement text on a modify, else undefined.
//   wireAfterV1(hooks) / wireAfterV2(hook): the security feedback wiring of
//     each contract (the text observer returns is appended to the tool's
//     output); set only when the post-tool block is rendered.
//   bus / busEvent: the observe-only events.
function opencodeHandlers(cwd, client) {
  const gateEvents = { "tool.execute.before": true, "chat.message": true };
  const h = { toolBefore: null, prompt: null, wireAfterV1: null, wireAfterV2: null, bus: [], busEvent: null };
  if (has("tool.execute.before")) {
    h.toolBefore = async (sid, tool, args, callID) => {
      const v = await gate(
        "tool.execute.before",
        envelope("tool.execute.before", sid, cwd, { tool_name: str(tool), tool_input: args || {}, call_id: str(callID) }),
      );
      if (blocks(v)) {
        toast(client, "Tool call blocked: " + v.reason, v.decision === "ask" ? "warning" : "error", 8000);
        throw new Error(v.reason);
      }
      if (v.message) toast(client, v.message, "warning", 6000);
    };
  }
  if (has("chat.message")) {
    // A THROW rejects the prompt before the host stores it, so the model is
    // never called (opencode 1.18.31, live 2026-10-15). The host shows only a
    // generic server error, so the reason rides a toast.
    h.prompt = async (sid, text) => {
      const v = await gate("chat.message", envelope("chat.message", sid, cwd, { prompt: text }));
      if (blocks(v)) {
        toast(client, "Your message was not sent: " + v.reason, v.decision === "ask" ? "warning" : "error", 10000);
        throw new Error(v.reason);
      }
      if (v.decision !== "modify" || typeof v.prompt !== "string") {
        if (v.message) toast(client, v.message, "warning", 8000);
        return undefined;
      }
      toast(client, v.message || "Your message was changed before it reached the model.", "info", 5000);
      return v.prompt;
    };
  }
// @@OBSERVER_SHIM_POSTTOOL_BEGIN
  // Security feedback after a tool ran (component security.feedback, lane
  // sec-h). Rendered only while the component is selected: otherwise
  // internal/hook/pluginshim drops this block. observer's reply carries up
  // to three templated lines in `context`, appended to the tool's output,
  // which the model reads as the tool result (Kilo CLI 7.3.54 live, JSP-6).
  // Any failure leaves the output alone: feedback never blocks.
  gateEvents["tool.execute.after"] = true;
  if (has("tool.execute.after")) {
    const toolAfter = async (sid, tool, args, callID) => {
      try {
        const r = await run(
          "tool.execute.after",
          envelope("tool.execute.after", sid, cwd, { tool_name: str(tool), tool_input: args || {}, call_id: str(callID) }),
          PROFILE.observe_ms,
        );
        return r && r.reply && typeof r.reply.context === "string" ? r.reply.context : "";
      } catch (_e) {
        return "";
      }
    };
    // v1: the hooks object's tool.execute.after(input, output).
    h.wireAfterV1 = (hooks) => {
      hooks["tool.execute.after"] = async (i, o) => {
        const extra = await toolAfter(i && i.sessionID, i && i.tool, i && i.args, i && i.callID);
        if (extra && o && typeof o.output === "string") o.output = o.output + "\n\n" + extra;
      };
    };
    // v2: context.tool.hook("execute.after"), whose payload carries the
    // result to append to.
    h.wireAfterV2 = (hook) =>
      hook("tool", "execute.after", async (ev) => {
        const extra = await toolAfter(ev && ev.sessionID, ev && ev.tool, pick(ev, ["input", "args"]), ev && ev.id);
        const res = ev && ev.result;
        if (extra && res && typeof res.output === "string") res.output = res.output + "\n\n" + extra;
      });
  }
// @@OBSERVER_SHIM_POSTTOOL_END
  h.bus = Object.keys(PROFILE.events).filter((e) => !gateEvents[e] && !e.startsWith("experimental."));
  if (h.bus.length) {
    h.busEvent = (ev) => {
      if (!ev || !h.bus.includes(ev.type)) return;
      const props = ev.properties || ev.data || {};
      const sid = pick(props, ["sessionID", "sessionId"]) || pick(props.info || {}, ["id"]);
      observe(ev.type, envelope(ev.type, sid, cwd, {}));
    };
  }
  return h;
}

// opencodeServer is the v1 contract (OpenCode 1.x, Kilo CLI): server(input)
// returns a hooks object keyed by native event name. A v1 loader reads only
// id, server and tui on the default export, so the v2 setup beside them is
// ignored there.
async function opencodeServer(input) {
  // One path per host (FU-188): a host whose setup already took the v2
  // path gets no second set of hooks here.
  if (opencodePath === "v2") return {};
  opencodePath = "v1";
  const cwd = (input && (input.directory || input.worktree)) || process.cwd();
  const client = input && input.client;
  const h = opencodeHandlers(cwd, client);
  const hooks = {};
  if (h.toolBefore) {
    hooks["tool.execute.before"] = (i, o) => h.toolBefore(i && i.sessionID, i && i.tool, o && o.args, i && i.callID);
  }
  if (h.prompt) {
    hooks["chat.message"] = async (i, o) => {
      const parts = o && Array.isArray(o.parts) ? o.parts : [];
      const texts = parts.filter((p) => p && p.type === "text" && typeof p.text === "string");
      if (!texts.length) return;
      const replacement = await h.prompt(i && i.sessionID, texts.map((p) => p.text).join("\n"));
      if (replacement === undefined) return;
      texts[0].text = replacement;
      for (let k = parts.length - 1; k >= 0; k--) {
        if (parts[k] !== texts[0] && texts.includes(parts[k])) parts.splice(k, 1);
      }
    };
  }
  if (h.wireAfterV1) h.wireAfterV1(hooks);
  if (h.busEvent) hooks.event = async (arg) => h.busEvent(arg && arg.event);
  return hooks;
}

// opencodeSetup is the v2 contract (OpenCode 2.x CLI and Desktop, FU-121):
// the loader requires a default export {id, effect} or {id, setup} ("Plugin
// must export a default definition with an id and an effect or setup
// function", OpenCode Desktop 2.2.0, MAC-5) and calls setup(context). The
// hooks are registered on the context's domains, grounded in the
// @opencode-ai/cli (`opencode2`) build 0.0.0-beta-19271 (2026-09-07):
//   context.tool.hook("execute.before", fn): fn({tool, sessionID, agent,
//     messageID, id, input}); a rejected fn fails the tool call.
//   context.session.hook("prompt", fn): fn({sessionID, messageID, prompt:
//     {text, files, agents, skills}, metadata, delivery}); the host reads
//     prompt back after the hook, so a modify rewrites prompt.text, and a
//     rejected fn fails the prompt.
//   context.tool.hook("execute.after", fn): fn({..., status, result:
//     {output, content, metadata}}) (the post-tool block wires it).
//   context.event.subscribe(fn): the observe-only bus.
//   context.location.directory: the project directory.
// A registration resolves to {dispose} (the host's AISDK.hook / tool.hook
// shape); one that throws, rejects, or resolves to anything else (a lazy
// Effect-style value the host never ran, a host without the domain) left
// the event unhooked. For a gate event that is recorded like any other
// gate failure (spooled fail_open, or fail_closed under a fresh enforced
// posture) and named once on stderr, so a silently unguarded host is
// visible to the doctor and the developer. Nothing here throws out of
// setup: the host keeps working when the shim cannot run.
const opencodeV2Events = { "tool/execute.before": "tool.execute.before", "session/prompt": "chat.message" };

// opencodePath is the one contract this module serves in its host (FU-188):
// "v1" once server ran, "v2" once setup took the v2 path. Kilo CLI 7.8.x, a
// v1 host, calls setup too (with its v1 input, which carries none of the v2
// domains): before this, that call tried to register the v2 hooks, failed,
// printed "could not register" and spooled a register failure for every
// gate although server's hooks block (MAC-6 account-free run 2026-10-29).
let opencodePath = "";

// opencodeIsV2Context reports whether setup's argument is a v2 context: it
// carries the project location or a tool / session hook domain. A v1 input
// ({client, project, directory, worktree, $}) carries none of them.
function opencodeIsV2Context(ctx) {
  if (!ctx || typeof ctx !== "object") return false;
  if (ctx.location && typeof ctx.location === "object") return true;
  return ["tool", "session"].some((d) => ctx[d] && typeof ctx[d].hook === "function");
}

async function opencodeSetup(context) {
  if (opencodePath === "v1" || !opencodeIsV2Context(context)) return;
  opencodePath = "v2";
  const ctx = context || {};
  const cwd = (ctx.location && ctx.location.directory) || process.cwd();
  const h = opencodeHandlers(cwd, null);
  const hook = async (domain, name, fn) => {
    let ok = false;
    try {
      const d = ctx[domain];
      if (d && typeof d.hook === "function") {
        const r = await d.hook(name, fn);
        ok = !!r && typeof r.dispose === "function";
      }
    } catch (_e) {
      ok = false;
    }
    if (!ok) {
      const event = opencodeV2Events[domain + "/" + name] || domain + "." + name;
      const cap = capOf(event);
      if (isGate(cap)) {
        spool(event, cap, "", "register", failsClosed(cap) ? "fail_closed" : "fail_open");
        try {
          console.error("superbased-observer: could not register the " + event + " gate with this OpenCode host; that gate is not running");
        } catch (_e) {
          // best effort
        }
      }
    }
    return ok;
  };
  if (h.toolBefore) {
    await hook("tool", "execute.before", (ev) => h.toolBefore(ev && ev.sessionID, ev && ev.tool, pick(ev, ["input", "args"]), ev && ev.id));
  }
  if (h.prompt) {
    await hook("session", "prompt", async (ev) => {
      const p = ev && ev.prompt;
      if (!p || typeof p.text !== "string" || p.text === "") return;
      const replacement = await h.prompt(ev.sessionID, p.text);
      if (replacement !== undefined) p.text = replacement;
    });
  }
  if (h.wireAfterV2) await h.wireAfterV2(hook);
  if (h.busEvent) {
    try {
      const ev = ctx.event;
      if (ev && typeof ev.subscribe === "function") await ev.subscribe((e) => h.busEvent(e));
    } catch (_e) {
      // observe-only: a host without the bus records nothing
    }
  }
}

// opencodePlugin is one default export for both contracts: v1 hosts read
// server, v2 hosts read setup.
function opencodePlugin() {
  return { id: "superbased-observer", server: opencodeServer, setup: opencodeSetup };
}

// --- pi: default-exported extension factory ---------------------------------

function piSession(ctx) {
  try {
    const sm = ctx && ctx.sessionManager;
    if (!sm) return "";
    if (typeof sm.getSessionId === "function") return str(sm.getSessionId());
    return str(sm.sessionId);
  } catch (_e) {
    return "";
  }
}

// piUI returns ctx.ui when the session has a UI (TUI or RPC; print / json
// mode has none), else null.
function piUI(ctx) {
  try {
    return ctx && ctx.hasUI && ctx.ui ? ctx.ui : null;
  } catch (_e) {
    return null;
  }
}

// piTell shows the developer a notice: ctx.ui.notify(message, level) with a
// UI, else (only for a stop, so a print-mode run still says why) one stderr
// line. Never throws.
function piTell(ctx, message, level) {
  try {
    const ui = piUI(ctx);
    if (ui && typeof ui.notify === "function") {
      ui.notify("SuperBased Observer: " + message, level);
      return;
    }
    if (level === "error") process.stderr.write("SuperBased Observer: " + message + "\n");
  } catch (_e) {
    // a broken UI never breaks the hook
  }
}

// piConfirm opens pi's native confirm when the session has a UI, bounded by
// the gate deadline. Returns true (go ahead), false (no, or the dialog timed
// out) or null (no UI: the caller falls back to a stop).
async function piConfirm(ctx, title, message) {
  const ui = piUI(ctx);
  if (!ui || typeof ui.confirm !== "function") return null;
  try {
    return (await ui.confirm(title, message, { timeout: PROFILE.gate_ms })) === true;
  } catch (_e) {
    return false;
  }
}

// piInputAction maps a prompt verdict onto pi's input-event result
// (InputEventResult: continue / transform {text, images} / handled, pi
// 1.0.0 extensions/types.ts).
async function piInputAction(v, ctx, event) {
  if (v.decision === "deny") {
    piTell(ctx, "Your message was not sent: " + v.reason, "error");
    return { action: "handled" };
  }
  if (v.decision === "ask") {
    const ok = await piConfirm(ctx, "SuperBased Observer: send this message anyway?", v.reason);
    if (ok === true) return { action: "continue" };
    // No UI: the stop the developer resends to confirm (reconsider-once).
    piTell(ctx, "Your message was not sent: " + v.reason, ok === null ? "error" : "warning");
    return { action: "handled" };
  }
  if (v.decision === "modify" && typeof v.prompt === "string") {
    piTell(ctx, v.message || "Your message was changed before it reached the model.", "info");
    const out = { action: "transform", text: v.prompt };
    if (event && Array.isArray(event.images)) out.images = event.images;
    return out;
  }
  if (v.message) piTell(ctx, v.message, "warning");
  return { action: "continue" };
}

function piExtension() {
  return function (pi) {
    if (has("input")) {
      // A throw in pi's input handler FAILS OPEN, so nothing may escape:
      // any failure on Observer's side is settled through failed(), the
      // same fail-closed posture rule every gate follows.
      pi.on("input", async (event, ctx) => {
        let sid = "";
        try {
          if (event && event.source === "extension") return { action: "continue" };
          const text = str(event && event.text);
          if (!text) return { action: "continue" };
          sid = piSession(ctx);
          const v = await gate("input", envelope("input", sid, ctx && ctx.cwd, { prompt: text }));
          return await piInputAction(v, ctx, event);
        } catch (_e) {
          try {
            const v = failed("input", capOf("input"), sid, "crash");
            if (blocks(v)) {
              piTell(ctx, v.reason, "error");
              return { action: "handled" };
            }
          } catch (_e2) {
            // fall through to continue: nothing said this gate fails closed
          }
          return { action: "continue" };
        }
      });
    }
    if (has("tool_call")) {
      pi.on("tool_call", async (event, ctx) => {
        const v = await gate(
          "tool_call",
          envelope("tool_call", piSession(ctx), ctx && ctx.cwd, {
            tool_name: str(event && event.toolName),
            tool_input: (event && event.input) || {},
            call_id: str(event && event.toolCallId),
          }),
        );
        if (v.decision === "ask" && PROFILE.ask) {
          const ok = await piConfirm(ctx, "SuperBased Observer: allow this tool call?", v.reason);
          if (ok === true) return undefined;
        }
        if (blocks(v)) {
          piTell(ctx, "Tool call blocked: " + v.reason, "error");
          return { block: true, reason: v.reason };
        }
        if (v.message) piTell(ctx, v.message, "warning");
        return undefined;
      });
    }
  };
}

// --- OpenClaw: plugin entry with register(api) -------------------------------

function openclawPlugin() {
  return {
    id: "superbased-observer",
    name: "SuperBased Observer",
    description: "Observer guard tool gate.",
    register(api) {
      if (!has("before_tool_call")) return;
      api.on(
        "before_tool_call",
        async (event, ctx) => {
          const v = await gate(
            "before_tool_call",
            envelope("before_tool_call", pick(ctx, ["sessionId", "sessionKey"]), "", {
              tool_name: str(event && event.toolName),
              tool_input: (event && event.params) || {},
              call_id: str(event && event.toolCallId),
            }),
          );
          if (v.decision === "ask" && PROFILE.ask) {
            return { requireApproval: { title: "SuperBased Observer guard", description: v.reason, severity: "warning" } };
          }
          if (blocks(v)) return { block: true, blockReason: v.reason };
          return undefined;
        },
        { timeoutMs: PROFILE.gate_ms + PROFILE.margin_ms },
      );
    },
  };
}

// --- DeepSeek Harness: Cordis plugin ------------------------------------------

function cordisPlugin() {
  return {
    name: "superbased-observer",
    apply(ctx) {
      if (!has("tools/pre-execute")) return;
      ctx.on("tools/pre-execute", async (exec, next) => {
        const tool = pick(exec, ["name", "toolName"]) || pick((exec && exec.tool) || {}, ["name"]);
        const v = await gate(
          "tools/pre-execute",
          envelope("tools/pre-execute", pick(exec, ["sessionId", "session_id"]), pick(exec, ["cwd"]), {
            tool_name: str(tool),
            tool_input: pick(exec, ["input", "args", "arguments", "params"]) || {},
            call_id: str(pick(exec, ["id", "callId", "toolCallId"])),
          }),
        );
        if (blocks(v)) return { kind: "deny", reason: v.reason };
        return next();
      });
    },
  };
}

// --- commandcode: Mods SDK default-exported factory ---------------------------

function commandcodeMod() {
  return function (cmd) {
    const hooks = {};
    if (has("transformInput")) {
      // Synchronous, and the payload is exactly {text}: the contract the
      // command-code prompt dialect (internal/hook/promptsubmit.go) reads.
      hooks.transformInput = ({ text }) => {
        const cap = capOf("transformInput");
        const r = runSync("transformInput", { text }, PROFILE.gate_ms);
        if (r.reply) {
          if (r.reply.action === "handled") return { action: "handled", message: r.reply.message };
          if (r.reply.action === "transform" && typeof r.reply.text === "string") {
            return { action: "transform", text: r.reply.text };
          }
          return { action: "continue" };
        }
        const v = failed("transformInput", cap, "", r.kind);
        return blocks(v) ? { action: "handled", message: v.reason } : { action: "continue" };
      };
    }
    if (has("beforeToolCall")) {
      hooks.beforeToolCall = async (arg) => {
        const v = await gate(
          "beforeToolCall",
          envelope("beforeToolCall", "", "", {
            tool_name: str(arg && arg.toolName),
            tool_input: (arg && arg.input) || {},
            call_id: str(arg && arg.toolCallId),
          }),
        );
        if (blocks(v)) return { block: true, additionalContext: v.reason };
        return undefined;
      };
    }
    cmd.hooks(hooks);
  };
}

// --- Cline CLI: Plugin API module {name, manifest, setup, hooks} -------------
//
// Cline CLI loads $CLINE_DIR/plugins/*.js (default ~/.cline/plugins) and runs
// it in a sandbox subprocess under Node, so nothing written to stdout or
// stderr reaches the developer. Grounded live on cline 3.0.68 (demo node 1,
// 2026-10-15): setup(api, ctx) carries ctx.session.sessionId (the id the
// session store uses) and ctx.workspaceInfo.rootPath; beforeModel runs
// before EVERY model call with ctx.request.messages and {stop: true, reason}
// ends the turn before any request (the reason is shown nowhere); a returned
// {messages} rewrites only that one request, and a stopped or rewritten user
// message stays in the history, so every remembered withhold or redaction is
// applied again on every later call. beforeTool sees ctx.toolCall
// {toolName, toolCallId} and ctx.input: {skip: true, reason} refuses that one
// call (the model gets the reason, the run continues), and
// {policy: {autoApprove: false}} raises Cline's own y/N approval.

const CLINE_WITHHELD = "[SuperBased Observer withheld this message from the model]";
// Remembered user messages per plugin process; only allowed ones are ever
// evicted, so a withheld or redacted message is never sent raw again.
const CLINE_MAX_REMEMBERED = 2000;

function clineText(msg) {
  const c = msg && msg.content;
  if (typeof c === "string") return c;
  if (!Array.isArray(c)) return "";
  return c
    .filter((p) => p && p.type === "text" && typeof p.text === "string")
    .map((p) => p.text)
    .join("\n");
}

// clineWithText returns a copy of msg whose text is text: the first text
// part carries it, other text parts are dropped, non-text parts are kept.
function clineWithText(msg, text) {
  const c = msg && msg.content;
  if (!Array.isArray(c)) return Object.assign({}, msg, { content: text });
  const out = [];
  let placed = false;
  for (const p of c) {
    if (p && p.type === "text") {
      if (!placed) {
        out.push(Object.assign({}, p, { text }));
        placed = true;
      }
      continue;
    }
    out.push(p);
  }
  if (!placed) out.unshift({ type: "text", text });
  return Object.assign({}, msg, { content: out });
}

function clineKey(msg) {
  if (msg && typeof msg.id === "string" && msg.id) return "id:" + msg.id;
  return "text:" + clineText(msg);
}

function clinePlugin() {
  let session = "";
  let root = "";
  // message key -> replacement text (withheld or redacted), or null (allowed)
  const seen = new Map();
  const remember = (k, v) => {
    if (seen.size >= CLINE_MAX_REMEMBERED && !seen.has(k)) {
      for (const [key, val] of seen) {
        if (val === null) {
          seen.delete(key);
          break;
        }
      }
    }
    seen.set(k, v);
  };
  const sid = (ctx) => session || str(ctx && ctx.snapshot && ctx.snapshot.conversationId);
  const hooks = {};
  if (has("beforeModel")) {
    hooks.beforeModel = async (ctx) => {
      const msgs = ctx && ctx.request && Array.isArray(ctx.request.messages) ? ctx.request.messages : [];
      let lastUser = -1;
      for (let i = msgs.length - 1; i >= 0; i--) {
        if (msgs[i] && msgs[i].role === "user") {
          lastUser = i;
          break;
        }
      }
      let stop = null;
      // Every user message this process has not judged yet, oldest first: a
      // resumed session's history is judged once too. Only the newest one can
      // stop the turn; an older one found blocked is withheld silently.
      for (let i = 0; i < msgs.length; i++) {
        const m = msgs[i];
        if (!m || m.role !== "user") continue;
        const k = clineKey(m);
        if (seen.has(k)) continue;
        const text = clineText(m);
        if (!text) {
          remember(k, null);
          continue;
        }
        const v = await gate("beforeModel", envelope("beforeModel", sid(ctx), root, { prompt: text }));
        if (blocks(v)) {
          remember(k, CLINE_WITHHELD);
          if (i === lastUser) stop = v.reason;
        } else if (v.decision === "modify" && typeof v.prompt === "string") {
          remember(k, v.prompt);
        } else {
          remember(k, null);
        }
      }
      let changed = false;
      const out = msgs.map((m) => {
        if (!m || m.role !== "user") return m;
        const r = seen.get(clineKey(m));
        if (typeof r !== "string") return m;
        changed = true;
        return clineWithText(m, r);
      });
      if (stop !== null) return changed ? { stop: true, reason: stop, messages: out } : { stop: true, reason: stop };
      return changed ? { messages: out } : undefined;
    };
  }
  if (has("beforeTool")) {
    hooks.beforeTool = async (ctx) => {
      const call = (ctx && ctx.toolCall) || {};
      const v = await gate(
        "beforeTool",
        envelope("beforeTool", sid(ctx), root, {
          tool_name: str(call.toolName) || str(ctx && ctx.tool && ctx.tool.name),
          tool_input: (ctx && ctx.input) || call.input || {},
          call_id: str(call.toolCallId),
        }),
      );
      if (v.decision === "ask" && PROFILE.ask) return { policy: { autoApprove: false } };
      if (blocks(v)) return { skip: true, reason: v.reason };
      return undefined;
    };
  }
  return {
    name: "superbased-observer",
    manifest: { capabilities: ["hooks"] },
    setup(_api, ctx) {
      try {
        const s = ctx && ctx.session && ctx.session.sessionId;
        if (typeof s === "string" && s) session = s;
        const r = ctx && ctx.workspaceInfo && ctx.workspaceInfo.rootPath;
        if (typeof r === "string" && r) root = r;
      } catch (_e) {
        // a context we cannot read leaves the snapshot fallback in place
      }
      return undefined;
    },
    hooks,
  };
}

const SHAPES = {
  opencode: opencodePlugin,
  pi: piExtension,
  openclaw: openclawPlugin,
  cordis: cordisPlugin,
  commandcode: commandcodeMod,
  cline: clinePlugin,
};

function entry() {
  try {
    const make = SHAPES[PROFILE.shape];
    if (make) return make();
  } catch (_e) {
    // fall through to the inert entry
  }
  return { id: "superbased-observer", server: async () => ({}), setup: async () => {} };
}

// Exposed for the shim's own tests only (a property on the default export,
// never a second named export: OpenCode's legacy loader rejects a module
// with a non-function export).
const ENTRY = entry();
try {
  Object.defineProperty(ENTRY, "__observerShim", { value: { gate, gateSync, PROFILE }, enumerable: false });
} catch (_e) {
  // a frozen entry simply has no test handle
}

export default ENTRY;
