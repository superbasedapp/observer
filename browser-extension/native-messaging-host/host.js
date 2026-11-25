#!/usr/bin/env node
// host.js — native-messaging stdio host for the SuperBased Observer browser
// extension (Phase 1).
//
// The browser launches this process and speaks Chrome's native-messaging wire
// protocol over stdio: each message is a 4-byte little-endian uint32 length
// prefix followed by that many bytes of UTF-8 JSON. For every captured-turn
// message the browser sends, this host invokes
//   observer browser hook <event>
// with the payload JSON on the child's STDIN — the same landing point the
// loopback listener funnels into. The <event> is "health" for a health
// beacon (payload.type === "health") and "capture" for every other message.
// It then replies (framed) — see the reply-after-exit contract below — so the
// extension's sendNativeMessage callback resolves. A successful ingest replies
// {status:"ok"}; a spawn failure / non-zero child exit / kill signal replies a
// bounded {status:"error", ...} so the extension's non-ok warning path fires.
//
// NOTE: this file has a byte-identical twin. The two copies are
//   internal/browserhost/hostfiles/host.js         (the go:embed SHIPPED copy,
//                                                    written by `observer init
//                                                    --browser`)
//   browser-extension/native-messaging-host/host.js (the standalone repo copy)
// A Go test (internal/browserhost/browserhost_test.go::TestHostFilesByteIdentical)
// byte-compares them, so they can never drift. Edit BOTH, identically, or the
// test fails.
//
// REPLY-AFTER-EXIT CONTRACT (fire-and-forget events only — "capture" and
// "health", i.e. every payload EXCEPT type:"config"): the host DEFERS its
// reply until the spawned `observer browser hook` child has EXITED (its
// payload written to stdin and stdin closed FIRST, as before). This is
// load-bearing on the Windows→WSL bridge. Chrome's sendNativeMessage is
// one-shot: it tears the native host down the instant the reply resolves.
// On Linux-native Chrome that kills only THIS node process and the observer
// grandchild survives to finish its DB write — so the old immediate ack was
// fine. But over the Windows bridge (Chrome → .bat → wsl.exe →
// host-launcher.sh → this host) Chrome's job-object teardown kills
// cmd.exe + wsl.exe, and the wsl.exe death terminates the whole WSL-side
// session — INCLUDING the just-spawned observer child, so the ingest dies
// mid-flight and the turn is lost with ZERO drop telemetry (the child dies
// before it can write health.json). Holding the reply until the child exits
// keeps Chrome — and therefore the wsl.exe relay and the WSL-side child —
// alive until the ingest is durable.
//
// Safety cap: if the child hasn't exited within HOST_INGEST_CAP_MS (40s) the
// host replies {status:"ok"} anyway and leaves the child running — worst case
// is exactly the old fire-and-forget behavior; the host must never hang Chrome
// forever. That cap MUST exceed the daemon's end-to-end Go ingest bound; see
// HOST_INGEST_CAP_MS below for the cross-reference that keeps them in sync.
//
// Because the reply is deferred, frames are processed SERIALLY: the host
// awaits one frame's reply — WRITTEN AND FLUSHED — before reading the next
// from the stdin buffer, so any queued frame (rare — sendNativeMessage is one
// host per message, but the buffer loop stays defensive) still replies IN
// ORDER, and the process never exits with a reply half-written (see
// writeMessage / maybeExit — a forced process.exit() would truncate a pending
// pipe write and Chrome would see a disconnected host instead of the ack).
//
// A config REQUEST (payload.type === "config") is the exception to the fire-
// and-forget shape: the host spawns `observer browser hook config`, captures
// its single JSON stdout line (the daemon's effective browser policy), and
// replies with THAT instead of {status:"ok"} — this is how the extension
// follows the daemon's configured granularity ceiling with no user config.
//
// The observer binary is resolved from the OBSERVER_BIN env var (set in the
// host launcher or the environment); it defaults to "observer" on PATH. An
// optional OBSERVER_CONFIG env var is forwarded as --config so the hook writes
// to the same observer.db the daemon uses.
//
// This host never crashes on a bad message or a torn pipe: parse/spawn errors
// are logged to stderr (which the browser surfaces in the extension's
// native-messaging error) and the loop continues; async stream errors (an
// EPIPE when Chrome or the Go child tears its end down) are caught and settled
// through the same exactly-once path rather than thrown.

"use strict";

const { spawn } = require("child_process");

const OBSERVER_BIN = process.env.OBSERVER_BIN || "observer";
const OBSERVER_CONFIG = process.env.OBSERVER_CONFIG || "";

// HOST_INGEST_CAP_MS bounds how long the host waits for the ingest child to
// EXIT before it replies anyway and leaves the child running (the safety
// escape from the reply-after-exit contract). It MUST exceed the daemon's
// end-to-end Go ingest bound so a legitimately slow ingest is never cut off by
// a premature reply + Chrome teardown. That Go bound is enforced at
// config.maxBrowserIngestTimeoutMS (35000ms in internal/config/browser.go — the
// clamp/validation on [browser].ingest_timeout_ms, which now covers
// db.Open + ingest end-to-end, not just the insert); this 40000ms cap keeps a
// ~5s margin above it. Keep the two in sync — the config constant carries the
// matching cross-reference comment.
const HOST_INGEST_CAP_MS = 40000;

// CONFIG_TIMEOUT_MS bounds the config request's stdout wait.
const CONFIG_TIMEOUT_MS = 3000;

// CONFIG_FALLBACK is the fail-closed daemon policy the host replies with when
// the config request can't be answered (spawn / timeout / parse failure). It
// mirrors the daemon's own safe default: usage_only granularity (no content
// constructed), rail enabled, no per-site overrides. `degraded` lets the
// extension tell a real policy from this fallback.
const CONFIG_FALLBACK = {
  type: "config",
  granularity: "usage_only",
  enabled: true,
  sites: {},
  degraded: true,
};

// A torn-down Chrome pipe surfaces as an async 'error' on process.stdout
// (EPIPE). Swallow it: nothing can be done once the reader is gone, and an
// unhandled 'error' event would crash the host. Individual writes settle their
// caller via the write callback regardless (see writeMessage).
process.stdout.on("error", (e) => {
  process.stderr.write(`[sbo-host] stdout error: ${e && e.message}\n`);
});

// writeMessage frames obj as a SINGLE buffer (4-byte LE length prefix +
// UTF-8 JSON) and writes it in ONE write() call, invoking cb only AFTER that
// write has settled — i.e. the bytes are flushed to the OS. Settling from the
// write callback (never before) is what lets the caller advance the frame loop
// / exit the process WITHOUT truncating a still-buffered pipe write: the old
// code queued two writes and then let a synchronous process.exit(0) drop them,
// so Chrome saw 0 bytes instead of the ack. Backpressure is handled implicitly
// — write()'s callback fires only once the chunk drains. If the write errors
// (EPIPE — Chrome tore the pipe down mid-reply) we still settle so the loop
// makes progress; the process-level 'error' handler above keeps us alive.
function writeMessage(obj, cb) {
  const json = Buffer.from(JSON.stringify(obj), "utf8");
  const header = Buffer.alloc(4);
  header.writeUInt32LE(json.length, 0);
  const frame = Buffer.concat([header, json]);
  const done = typeof cb === "function" ? cb : () => {};
  let settled = false;
  const settle = () => {
    if (settled) return;
    settled = true;
    done();
  };
  process.stdout.write(frame, () => settle());
}

// eventForPayload picks the `observer browser hook <event>` subcommand for a
// message. A health beacon (payload.type === "health") lands on the health
// event; everything else is a captured turn.
function eventForPayload(payload) {
  if (payload && payload.type === "health") return "health";
  return "capture";
}

// boundedErrorReply builds the framed {status:"error", ...} reply from an
// ingest result whose ok===false. Every string field is length-bounded so a
// hostile / verbose child can't blow up the reply frame. The extension's
// existing non-ok branch console.warns on this, surfacing spawn failures and
// non-zero exits that the old code hid behind an unconditional {status:"ok"}.
function boundedErrorReply(result) {
  const reply = { status: "error" };
  if (result && result.error) reply.error = String(result.error).slice(0, 256);
  if (result && typeof result.exitCode === "number") reply.exitCode = result.exitCode;
  if (result && result.signal) reply.signal = String(result.signal).slice(0, 32);
  return reply;
}

// ingest funnels a fire-and-forget "capture"/"health" payload into
// `observer browser hook <event>` on the child's STDIN, then invokes done()
// EXACTLY ONCE with a RESULT object — from the child's 'exit', from an
// 'error', or from the HOST_INGEST_CAP_MS safety timer, whichever fires first.
// The result is {ok:true} on a clean (exit 0 / timed-out-still-running) run and
// {ok:false, error, exitCode?, signal?} on a spawn failure, non-zero exit, or
// kill signal — so the caller can reply {status:"ok"} vs a bounded
// {status:"error"} (findings: false-ok on failures). Deferring done() until the
// child exits is the reply-after-exit contract that keeps the Windows wsl.exe
// bridge (and the WSL-side child) alive until the ingest is durable (see the
// file header). The `settled` guard + clearTimeout make done() fire once and
// only once, so the timer-vs-exit race can never double-reply.
function ingest(payload, done) {
  const args = ["browser", "hook", eventForPayload(payload)];
  if (OBSERVER_CONFIG) args.push("--config", OBSERVER_CONFIG);
  let settled = false;
  let timer = null;
  const finish = (result) => {
    if (settled) return;
    settled = true;
    if (timer) clearTimeout(timer);
    done(result || { ok: true });
  };
  let child;
  try {
    child = spawn(OBSERVER_BIN, args, { stdio: ["pipe", "ignore", "inherit"] });
  } catch (e) {
    process.stderr.write(`[sbo-host] spawn failed: ${e && e.message}\n`);
    return finish({ ok: false, error: `spawn failed: ${e && e.message}` });
  }
  child.on("error", (e) => {
    process.stderr.write(`[sbo-host] child error: ${e && e.message}\n`);
    finish({ ok: false, error: `child error: ${e && e.message}` });
  });
  // Reply-after-exit: the reply waits for the child to terminate. A non-zero
  // exit or a kill signal is surfaced as an error result so the extension's
  // non-ok warning path fires. The HOST_INGEST_CAP_MS cap (> the daemon's Go
  // end-to-end ingest bound) guarantees a wedged child can never hang Chrome
  // forever — we then reply {status:"ok"} anyway and leave the child running,
  // i.e. the old fire-and-forget behavior (a still-running child is not a
  // failure).
  child.on("exit", (code, signal) => {
    if (signal) {
      finish({ ok: false, error: `child killed by signal ${signal}`, signal });
    } else if (code !== 0) {
      finish({ ok: false, error: `child exited with code ${code}`, exitCode: code });
    } else {
      finish({ ok: true, exitCode: 0 });
    }
  });
  timer = setTimeout(() => {
    process.stderr.write("[sbo-host] ingest child still running after cap; replying anyway\n");
    finish({ ok: true, timedOut: true });
  }, HOST_INGEST_CAP_MS);
  // Install the child-stdin error handler BEFORE writing: if the Go child
  // exits without draining its stdin (e.g. the over-limit keyed-drop path
  // reads only up to the cap+1 and returns), closing the pipe emits an async
  // EPIPE that a bare try/catch never sees and that would otherwise crash the
  // host. We DON'T finish() here — the child is still the durability owner and
  // its 'exit'/'error' (or the cap) drives the deferred reply; this handler
  // only prevents the async stream error from becoming an unhandled crash.
  child.stdin.on("error", (e) => {
    process.stderr.write(`[sbo-host] child stdin error: ${e && e.message}\n`);
  });
  try {
    child.stdin.write(JSON.stringify(payload));
    child.stdin.end();
  } catch (e) {
    process.stderr.write(`[sbo-host] write to child failed: ${e && e.message}\n`);
    // Don't finish() here: the child was spawned and is still the durability
    // owner. Its 'exit'/'error' (or the cap) drives the deferred reply.
  }
}

// requestConfig answers a config REQUEST (payload.type === "config"): unlike
// the fire-and-forget ingest path it spawns `observer browser hook config`
// NON-detached, captures its single JSON stdout line (the daemon's effective
// browser policy), and hands it to done() as the native-messaging response —
// so the extension can follow the daemon's configured granularity ceiling with
// zero user configuration. Bounded (64KB stdout cap, CONFIG_TIMEOUT_MS) and
// fail-closed: any spawn / timeout / parse failure resolves to CONFIG_FALLBACK.
// The child's stderr is inherited (config.Load's deprecation notices go there,
// so they never pollute the captured stdout JSON).
function requestConfig(payload, done) {
  const args = ["browser", "hook", "config"];
  if (OBSERVER_CONFIG) args.push("--config", OBSERVER_CONFIG);
  let settled = false;
  let timer = null;
  let child = null;
  const finish = (resp) => {
    if (settled) return;
    settled = true;
    if (timer) clearTimeout(timer);
    try {
      if (child) child.kill();
    } catch (_) {
      /* child already exited */
    }
    done(resp || CONFIG_FALLBACK);
  };
  try {
    child = spawn(OBSERVER_BIN, args, { stdio: ["pipe", "pipe", "inherit"] });
  } catch (e) {
    process.stderr.write(`[sbo-host] config spawn failed: ${e && e.message}\n`);
    return finish(CONFIG_FALLBACK);
  }
  timer = setTimeout(() => {
    process.stderr.write("[sbo-host] config request timed out\n");
    finish(CONFIG_FALLBACK);
  }, CONFIG_TIMEOUT_MS);
  let out = "";
  let capped = false;
  child.stdout.on("data", (chunk) => {
    if (capped) return;
    out += chunk.toString("utf8");
    if (out.length > 64 * 1024) {
      out = out.slice(0, 64 * 1024);
      capped = true;
    }
  });
  child.on("error", (e) => {
    process.stderr.write(`[sbo-host] config child error: ${e && e.message}\n`);
    finish(CONFIG_FALLBACK);
  });
  child.on("close", () => {
    let resp = null;
    const line = out
      .split("\n")
      .map((s) => s.trim())
      .find((s) => s.length > 0);
    if (line) {
      try {
        resp = JSON.parse(line);
      } catch (e) {
        process.stderr.write(`[sbo-host] config parse failed: ${e && e.message}\n`);
      }
    }
    finish(resp && resp.type === "config" ? resp : CONFIG_FALLBACK);
  });
  // Guard the config child's stdin the same way as the ingest child: the
  // config command never reads stdin, so closing the pipe can emit an async
  // EPIPE. Swallow it (best-effort; the 'close'/timeout drive the reply).
  child.stdin.on("error", (e) => {
    process.stderr.write(`[sbo-host] config child stdin error: ${e && e.message}\n`);
  });
  try {
    child.stdin.write(JSON.stringify(payload));
    child.stdin.end();
  } catch (e) {
    process.stderr.write(`[sbo-host] config write to child failed: ${e && e.message}\n`);
  }
}

// Native-messaging frame reader: buffer stdin, peel 4-byte-length-prefixed
// JSON messages as they complete, and process them SERIALLY. Because a fire-
// and-forget event's reply is deferred until its observer child exits (the
// reply-after-exit contract in the file header), we must not start the next
// frame until the current one has replied — otherwise deferred replies could
// interleave out of order. `processing` is the one-at-a-time gate; `queue`
// holds any frames that completed while a child was still running (rare —
// sendNativeMessage delivers one message per host — but the buffer loop stays
// defensive). Enqueued bodies are COPIED because `buf` is re-sliced and
// reallocated as more stdin arrives.
let buf = Buffer.alloc(0);
const queue = [];
let processing = false;

process.stdin.on("data", (chunk) => {
  buf = Buffer.concat([buf, chunk]);
  for (;;) {
    if (buf.length < 4) break;
    const len = buf.readUInt32LE(0);
    if (buf.length < 4 + len) break;
    queue.push(Buffer.from(buf.subarray(4, 4 + len)));
    buf = buf.subarray(4 + len);
  }
  pump();
});

// pump processes one queued frame at a time. The next() passed to the handler
// re-arms the pump only AFTER that frame's reply has been written AND FLUSHED,
// preserving reply ORDER across deferred replies and keeping the exit path
// (maybeExit) from truncating a still-buffered write.
function pump() {
  if (processing) return;
  const body = queue.shift();
  if (body === undefined) return maybeExit();
  processing = true;
  handleFrame(body, () => {
    processing = false;
    pump();
  });
}

// handleFrame parses one frame and dispatches it, invoking next() EXACTLY ONCE
// after the reply is written and flushed. A config request is REQUEST/RESPONSE:
// the reply is the daemon's policy (the ONLY stdout line the child prints), not
// the generic ack. Every other message is fire-and-forget ingest whose reply is
// DEFERRED until the child exits (or the cap): {status:"ok"} on success, a
// bounded {status:"error", ...} on a spawn failure / non-zero exit / signal. A
// malformed frame is logged and skipped with no reply, exactly as before.
function handleFrame(body, next) {
  let payload;
  try {
    payload = JSON.parse(body.toString("utf8"));
  } catch (e) {
    process.stderr.write(`[sbo-host] bad message json: ${e && e.message}\n`);
    return next();
  }
  if (payload && payload.type === "config") {
    requestConfig(payload, (resp) => {
      writeMessage(resp, next);
    });
  } else {
    ingest(payload, (result) => {
      const reply = result && result.ok === false ? boundedErrorReply(result) : { status: "ok" };
      writeMessage(reply, next);
    });
  }
}

// A stdin EOF means the browser is done with this host — but a deferred reply
// may still be in flight (the reply-after-exit contract above). Exit only once
// the queue has drained and no frame is mid-flight, so an early stdin close
// (e.g. the Windows wsl.exe-bridge teardown this contract exists to survive)
// can never truncate a pending reply. Re-checked whenever the pump goes idle.
//
// We END stdout and exit from its flush callback rather than calling
// process.exit(0) directly: process.exit() does NOT flush a pending pipe write,
// so a reply written just before EOF would be truncated to 0 bytes and Chrome
// would see a disconnected host instead of the ack. Because every reply settles
// its next() only from its own write callback (see writeMessage), by the time
// maybeExit runs the last reply's bytes are already flushed; ending stdout then
// draining to 'finish' before exit is belt-and-suspenders.
let stdinEnded = false;
let exiting = false;
function maybeExit() {
  if (!stdinEnded || processing || queue.length > 0 || exiting) return;
  exiting = true;
  process.stdout.end(() => process.exit(0));
}
process.stdin.on("end", () => {
  stdinEnded = true;
  maybeExit();
});
