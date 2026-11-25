// SPDX-License-Identifier: Apache-2.0
// Copyright (c) SuperBased. Part of SuperBased Observer.
//
// Per-site stream parsers for the browser-capture extension — the PURE half
// of content-main.js (the transport-patching IIFE stays there). Kept in its
// own UMD module, like tier1.js, so the SAME code loads into the MAIN
// content-script world (via the SBOParsers global) AND is `require`-able by
// the Node unit tests (src/parsers.test.js). ZERO extension-API / DOM
// dependencies.
//
// SITE = DATA / one parser factory per transport family (CLAUDE.md #3/#5):
// each site's request parser + streaming accumulator is a self-contained
// row the SITES table in content-main.js wires up; the transport-patching
// code is fully site-agnostic.
//
// The field paths encoded here come from July-2026 reverse-engineering of the
// live sites (see docs/plans/browser-extension-stream-shapes-2026-07-10.md).
// Items an operator's live capture must still confirm are flagged inline with
// `TODO(must-verify-live)`.
(function (root, factory) {
  "use strict";
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    root.SBOParsers = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : self, function () {
  "use strict";

  // --- text helpers --------------------------------------------------------
  // joinParts concatenates the STRING elements of a ChatGPT/Claude message
  // `content.parts` array (non-strings contribute nothing), joined with NO
  // separator — the parts reconstruct one streamed message body. Unlike the
  // newline-joining coerceContentText it must NOT insert delimiters or descend
  // into objects, so it can't simply delegate; instead it shares the SAME
  // node/byte budget (MAX_COERCE_PARTS / coercePushFragment) so a hostile huge
  // parts array can't pin the CPU or balloon memory here either (re-review HIGH
  // #2 — the unbounded-join class, not just its copilot instance, must die).
  function joinParts(parts) {
    if (!Array.isArray(parts)) return "";
    const acc = { texts: [], bytes: 0, nodes: 0, stopped: false };
    for (const p of parts) {
      if (acc.stopped) break;
      if (++acc.nodes > MAX_COERCE_PARTS) {
        acc.stopped = true;
        break;
      }
      if (typeof p === "string") coercePushFragment(p, acc);
    }
    return acc.texts.join("");
  }

  // MAX_CONTENT_FIELD_BYTES caps a single captured content field (prompt_text /
  // response_text) BEFORE a turn is emitted, well under the daemon's 8 MiB
  // ingest cap so one huge paste/answer can't be silently keyed-dropped by the
  // daemon backstop (which discards the WHOLE turn). 2 MiB per field leaves
  // ample headroom for the rest of the JSON envelope. This budget is counted in
  // JSON-WIRE BYTES (jsonWireByteLen) — the size the field occupies once
  // JSON.stringify serializes it — NOT raw UTF-8 bytes and NOT JS-string code
  // units. JSON escaping EXPANDS some characters (a control char → \u00XX = 6
  // bytes, a backslash/quote → 2, a lone surrogate → 6), so a raw-UTF-8 budget
  // let two 2 MiB backslash-heavy fields serialize to >8 MiB (NUL-heavy ~25 MiB)
  // and the daemon's 8 MiB ingest cap then dropped the whole turn. Capping in
  // wire bytes bounds each field's serialized size to ~2 MiB, so two fields +
  // envelope stay comfortably under 8 MiB. A capped CJK field also can't
  // serialize larger than its budget (3 wire bytes/char, unescaped). The Go
  // side mirrors this accounting (coerceAcc.push → jsonWireCost).
  const MAX_CONTENT_FIELD_BYTES = 2 * 1024 * 1024; // 2 MiB (JSON-wire bytes) per content field
  const CONTENT_TRUNCATION_MARKER = "\n…[truncated by SuperBased Observer]";

  // Traversal bounds for coerceContentText. A captured content value can be a
  // hostile payload (a stale/spoofed bridge, a site echoing an adversarial
  // shape): an ~5,000-deep nesting overflows the stack (RangeError), a huge
  // flat array pins the CPU, and a multi-MiB tree balloons memory. So the
  // traversal is bounded on THREE axes — nesting depth, total nodes visited,
  // and accumulated output bytes — and on ANY bound hit it KEEPS what it has
  // already accumulated (truncate, never nuke to empty: capture-something beats
  // drop-everything). MAX_COERCE_DEPTH/MAX_COERCE_PARTS mirror the Go
  // coerceFlexValue traversal exactly; the byte cap is MAX_CONTENT_FIELD_BYTES
  // (already the emission budget) so we never build more than survives.
  const MAX_COERCE_DEPTH = 8;
  const MAX_COERCE_PARTS = 256;
  // DoS ceiling for coercion accumulation: a small slack ABOVE the field cap so
  // the downstream capContentField still sees an over-cap result and appends
  // its legible truncation marker (finding 1 keeps the hard bound; the marker
  // stays capContentField's job). Slack ≫ the marker length, ≪ the cap, so an
  // 8 MiB hostile payload is still bounded to ~the field cap.
  const MAX_COERCE_BYTES = MAX_CONTENT_FIELD_BYTES + 4096;

  // jsonWireCharCost returns the number of BYTES one code point costs once
  // JSON.stringify serializes it onto the wire — NOT its raw UTF-8 width. JSON
  // escaping EXPANDS some characters: a control char (<0x20) becomes \u00XX
  // (6 bytes; a safe upper bound — \n\t etc. are really 2), a backslash or
  // double-quote becomes a 2-byte escape, and a LONE surrogate becomes \uXXXX
  // (6 bytes); everything else costs its UTF-8 width (a valid surrogate PAIR is
  // emitted raw = 4 bytes). `units` is how many UTF-16 code units the code point
  // consumed (2 for a surrogate pair, else 1). Returns { cost, units }.
  function jsonWireCharCost(s, i) {
    const c = s.charCodeAt(i);
    if (c < 0x20) return { cost: 6, units: 1 }; // control → \u00XX (upper bound)
    if (c === 0x22 || c === 0x5c) return { cost: 2, units: 1 }; // " or \ → escape
    if (c < 0x80) return { cost: 1, units: 1 };
    if (c < 0x800) return { cost: 2, units: 1 };
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) return { cost: 4, units: 2 }; // pair → raw
      return { cost: 6, units: 1 }; // lone high surrogate → \uXXXX
    }
    if (c >= 0xdc00 && c <= 0xdfff) return { cost: 6, units: 1 }; // lone low → \uXXXX
    return { cost: 3, units: 1 }; // BMP → 3 UTF-8 bytes
  }

  // jsonWireByteLen returns the number of BYTES a JS string occupies once
  // JSON.stringify serializes it onto the wire (finding 2), WITHOUT allocating —
  // it sums per-code-point wire costs (see jsonWireCharCost). Counting raw UTF-8
  // length undercounts a backslash/control/NUL-heavy field, so a 2 MiB field can
  // serialize to 8-25 MiB and the daemon's 8 MiB ingest cap then drops the WHOLE
  // turn. Cheap incremental scan; runs per fragment, never over the whole
  // accumulated string repeatedly.
  function jsonWireByteLen(s) {
    let bytes = 0;
    for (let i = 0; i < s.length; ) {
      const { cost, units } = jsonWireCharCost(s, i);
      bytes += cost;
      i += units;
    }
    return bytes;
  }

  // jsonWireSlicePrefix returns the longest PREFIX of s whose JSON-WIRE cost is
  // <= maxBytes, plus that prefix's exact wire-byte count — never splitting a
  // surrogate pair or overshooting the budget. Used to clamp an over-budget
  // fragment/field in wire bytes so the serialized payload honours the budget
  // even for escape-heavy or multibyte content.
  function jsonWireSlicePrefix(s, maxBytes) {
    if (maxBytes <= 0) return { text: "", bytes: 0 };
    let bytes = 0;
    let i = 0;
    while (i < s.length) {
      const { cost, units } = jsonWireCharCost(s, i);
      if (bytes + cost > maxBytes) break;
      bytes += cost;
      i += units;
    }
    return { text: s.slice(0, i), bytes };
  }

  // coercePushFragment appends one leaf text fragment to the accumulator,
  // clamped to the remaining JSON-WIRE BYTE budget (finding 2 — the budget is
  // the serialized size, not raw UTF-8 bytes and not code units). Once the
  // budget is spent it flips acc.stopped so the walk unwinds without discarding
  // what it kept.
  function coercePushFragment(s, acc) {
    if (!s) return;
    const remaining = MAX_COERCE_BYTES - acc.bytes;
    if (remaining <= 0) {
      acc.stopped = true;
      return;
    }
    const sBytes = jsonWireByteLen(s);
    if (sBytes >= remaining) {
      const cut = jsonWireSlicePrefix(s, remaining);
      acc.texts.push(cut.text);
      acc.bytes += cut.bytes;
      acc.stopped = true;
      return;
    }
    acc.texts.push(s);
    acc.bytes += sBytes;
  }

  // coerceCollect walks ONE content value under the shared shape contract —
  // string | array (of the same) | object with `text`/`content`/`parts` —
  // appending real text fragments to acc, bounded by depth / node-count /
  // bytes. Nested BARE arrays (an array element that is itself an array) and
  // top-level objects are traversed identically to the Go side. A non-text
  // leaf (number/bool/null/textless object) contributes nothing.
  function coerceCollect(v, depth, acc) {
    if (acc.stopped) return;
    if (++acc.nodes > MAX_COERCE_PARTS) {
      acc.stopped = true;
      return;
    }
    if (depth > MAX_COERCE_DEPTH) return; // too deep: drop this branch, keep the rest
    if (typeof v === "string") {
      coercePushFragment(v, acc);
      return;
    }
    if (Array.isArray(v)) {
      for (const part of v) {
        if (acc.stopped) return;
        coerceCollect(part, depth + 1, acc);
      }
      return;
    }
    if (v && typeof v === "object") {
      if (typeof v.text === "string") {
        coercePushFragment(v.text, acc);
        return;
      }
      if (v.text !== undefined && v.text !== null) {
        coerceCollect(v.text, depth + 1, acc); // pathological nested-array `.text`
        return;
      }
      if (Array.isArray(v.content)) {
        coerceCollect(v.content, depth + 1, acc);
        return;
      }
      if (Array.isArray(v.parts)) {
        coerceCollect(v.parts, depth + 1, acc);
        return;
      }
    }
    // number / bool / null / textless object: dropped.
  }

  // coercePartText pulls the text out of ONE content value (a bare string, an
  // object carrying `.text`, or a nested `.content`/`.parts` container). It is
  // a thin alias over the unified bounded traversal so both entry points share
  // one shape contract; kept for the exported-API contract.
  function coercePartText(part) {
    return coerceContentText(part);
  }

  // coerceContentText normalizes a captured content value to a plain STRING at
  // the emission boundary so the wire NEVER carries a non-string prompt_text /
  // response_text (the daemon's browserchat.Parse unmarshals both into a Go
  // `string`; an array previously hard-failed the WHOLE turn with `cannot
  // unmarshal array into ...prompt_text of type string`). A string passes
  // through; an ARRAY of message parts / adaptive-card segments is joined —
  // string elements verbatim, object elements via their `.text` (or a nested
  // `.content`/`.parts` container), non-text parts dropped — with "\n" between
  // distinct parts; anything else (number/null/bare object) degrades to "".
  // The traversal is bounded (see MAX_COERCE_* above) and mirrors the Go
  // coerceFlexValue decoder in internal/adapter/browserchat exactly so both
  // sides agree on the coercion.
  function coerceContentText(v) {
    const acc = { texts: [], bytes: 0, nodes: 0, stopped: false };
    coerceCollect(v, 0, acc);
    return acc.texts.join("\n");
  }

  // capContentField coerces one content value to a string (coerceContentText —
  // arrays of parts become one joined string; non-text degrades to "") then
  // clamps it to MAX_CONTENT_FIELD_BYTES, appending a clear truncation marker
  // when it trims. It is the single emission chokepoint content-main funnels
  // both prompt_text and response_text through, so a non-string can never reach
  // the wire regardless of which per-site parser produced the field.
  function capContentField(text, max) {
    const s = coerceContentText(text);
    const limit = typeof max === "number" && max > 0 ? max : MAX_CONTENT_FIELD_BYTES;
    // The budget is JSON-WIRE BYTES, not raw UTF-8 and not code units
    // (finding 2), so an escape-heavy or CJK field that fits in code units (or
    // raw bytes) but serializes larger is still clamped below the daemon's
    // ingest cap.
    if (jsonWireByteLen(s) <= limit) return s;
    // Reserve room for the marker (its own wire-byte width) so the RESULT stays
    // within the wire budget.
    const keep = Math.max(0, limit - jsonWireByteLen(CONTENT_TRUNCATION_MARKER));
    return jsonWireSlicePrefix(s, keep).text + CONTENT_TRUNCATION_MARKER;
  }

  // unwrapSchematizedAnswer peels Perplexity's schematized-API double wrap.
  // LIVE-CONFIRMED 2026-07-10: with `params.use_schematized_api = true`
  // (default on the pplx_pro_upgraded build), FINAL.content.answer is ITSELF a
  // JSON string `{"answer":"…", …}` rather than plain text — so a single
  // `.answer` read returns the opaque wrapper `{"answer": "The last king…"}`
  // instead of the prose. Peel any `{answer:string}` wrapper (bounded depth;
  // plain-text answers never parse as an object with a string `.answer`, so
  // legacy shapes are untouched).
  function unwrapSchematizedAnswer(s) {
    let cur = typeof s === "string" ? s : "";
    for (let i = 0; i < 4; i++) {
      const t = cur.trim();
      if (t.length < 2 || t.charCodeAt(0) !== 0x7b /* { */) break;
      let inner;
      try {
        inner = JSON.parse(t);
      } catch {
        break;
      }
      if (inner && typeof inner.answer === "string") {
        cur = inner.answer;
        continue;
      }
      break;
    }
    return cur;
  }

  // makeLineReader buffers a partial trailing line across feed() calls. A
  // network chunk boundary can fall MID-FRAME, so splitting each chunk on
  // "\n" in isolation silently drops any frame straddling two chunks (an
  // assistant snapshot cut in half loses its id/model, deltas vanish). push()
  // returns only the COMPLETE lines and retains the remainder; flush() returns
  // the final unterminated line (a stream may end without a trailing newline,
  // e.g. `data: [DONE]`). Used by every SSE accumulator below.
  function makeLineReader() {
    let pending = "";
    return {
      push(chunk) {
        pending += chunk;
        const lines = pending.split("\n");
        pending = lines.pop(); // keep the last (possibly incomplete) segment
        return lines;
      },
      flush() {
        const last = pending;
        pending = "";
        return last;
      },
    };
  }

  // --- two-leg correlator helpers (pure) -----------------------------------
  // A ChatGPT thinking turn splits across two SSE POSTs (leg 1 = prompt +
  // handoff-only preamble; leg 2 = `/resume` answer stream). Both legs carry a
  // per-turn correlator id we can pair on WITHOUT relying on the conversation
  // id (a new-chat leg 1 has none): the leg-1 `stream_handoff` frame's
  // `turn_exchange_id` / `options[].topic_id`, and the `resume_conversation_token`
  // JWT's `turn_topic_id` (present on both legs). These are the same underlying
  // exchange id in three spellings — `turn_exchange_id` is the raw `<tx>`,
  // `topic_id` / `turn_topic_id` are `conversation-turn-<tx>` — so normalize to
  // the raw `<tx>` before comparing. GROUNDED: scratchpad recon
  // (chatgpt-wire-findings.md, 2026-07-17 live capture) documents the conduit
  // JWT shape `{conduit_uuid, conduit_location, cluster, iat, exp, turn_topic_id}`.
  function normalizeTurnId(v) {
    if (typeof v !== "string" || !v) return "";
    return v.replace(/^conversation-turn-/, "");
  }

  // decodeJWTPayload base64url-decodes a JWT's middle (claims) segment to an
  // object. Pure + fail-soft (any malformed token → null). No signature check:
  // we only READ a public routing claim (turn_topic_id), never trust it for
  // auth. Works under Node (Buffer) and the browser (atob); the claim we read
  // is ASCII, so atob's binary-string output is lossless for it.
  function decodeJWTPayload(token) {
    if (typeof token !== "string") return null;
    // A well-formed JWT is EXACTLY three non-empty dot-separated segments
    // (header.claims.signature). Reject 2-segment (unsecured/malformed) and
    // 4+-segment (JWE / garbage) tokens outright rather than blindly decoding
    // whatever sits in position 2 — the stated contract is "malformed → null".
    const parts = token.split(".");
    if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) return null;
    const seg = parts[1];
    try {
      let b64 = seg.replace(/-/g, "+").replace(/_/g, "/");
      while (b64.length % 4) b64 += "=";
      let json;
      if (typeof atob === "function") {
        json = atob(b64);
      } else if (typeof Buffer !== "undefined") {
        json = Buffer.from(b64, "base64").toString("binary");
      } else {
        return null;
      }
      return JSON.parse(json);
    } catch {
      return null;
    }
  }

  // turnTopicFromJWT pulls the normalized exchange id out of a
  // resume_conversation_token JWT (`turn_topic_id` claim). "" on any failure.
  function turnTopicFromJWT(token) {
    const claims = decodeJWTPayload(token);
    return claims && typeof claims.turn_topic_id === "string"
      ? normalizeTurnId(claims.turn_topic_id)
      : "";
  }

  // handoffIdFromFrame pulls the normalized exchange id out of a parsed
  // `stream_handoff` frame: `turn_exchange_id` first, else the first
  // `options[].topic_id`. "" when neither is present.
  function handoffIdFromFrame(ev) {
    if (!ev || typeof ev !== "object") return "";
    const direct = normalizeTurnId(ev.turn_exchange_id);
    if (direct) return direct;
    const opts = Array.isArray(ev.options) ? ev.options : [];
    for (const o of opts) {
      if (o && typeof o.topic_id === "string") {
        const n = normalizeTurnId(o.topic_id);
        if (n) return n;
      }
    }
    return "";
  }

  // --- per-site request parsers --------------------------------------------
  // Each returns { prompt, model, conversationId } best-effort.
  function parseChatGPTRequest(bodyText) {
    const out = { prompt: "", model: "", conversationId: "" };
    if (!bodyText) return out;
    try {
      const j = JSON.parse(bodyText);
      // Model id: request body `model`. LIVE-CONFIRMED 2026-07-10: the
      // authenticated POST target carries the `/f/` segment
      // (`/backend-api/f/conversation`, with a `/prepare` debounce sibling) and
      // the model is at request `model` (observed "gpt-5-6-thinking").
      // TODO(must-verify-live): the server SSE echo key
      // (message.metadata.model_slug) is UNCONFIRMED — the captured turn was a
      // gpt-5-6-thinking one whose completion did NOT stream over this SSE leg
      // (see the conduit_token handoff note in the accumulator). The
      // accumulator still prefers model_slug when present.
      out.model = j.model || "";
      out.conversationId = j.conversation_id || "";
      const msgs = Array.isArray(j.messages) ? j.messages : [];
      for (let i = msgs.length - 1; i >= 0; i--) {
        const m = msgs[i];
        if (m && m.author && m.author.role === "user") {
          out.prompt = joinParts((m.content && m.content.parts) || []).trim();
          break;
        }
      }
    } catch {
      /* non-JSON — leave blank */
    }
    return out;
  }

  function parseClaudeRequest(bodyText) {
    // Claude.ai POST body on the completion endpoint: { prompt, model,
    // parent_message_uuid, ... }. LIVE-CONFIRMED 2026-07-10: prompt is a plain
    // string at `prompt`, model at `model` (observed value "claude-opus-4-8" —
    // the slug, no marketing alias). Other-shape probes retained defensively.
    const out = { prompt: "", model: "", conversationId: "" };
    if (!bodyText) return out;
    try {
      const j = JSON.parse(bodyText);
      out.model = j.model || "";
      out.prompt =
        (typeof j.prompt === "string" && j.prompt) ||
        (j.messages &&
          Array.isArray(j.messages) &&
          joinParts((j.messages[j.messages.length - 1] || {}).content || [])) ||
        "";
      // conversation id is in the URL path, resolved by the caller.
    } catch {
      /* ignore */
    }
    return out;
  }

  function parsePerplexityRequest(bodyText) {
    // Perplexity POST /rest/sse/perplexity_ask: { query_str, params:{
    // query_str, dsl_query, model_preference, frontend_uuid,
    // frontend_context_uuid, mode, ... } }. LIVE-CONFIRMED 2026-07-18: the
    // prompt is BOTH top-level `query_str` AND `params.query_str` /
    // `params.dsl_query`; the model is `params.model_preference` (observed
    // "turbo"); the per-turn request id is `params.frontend_uuid` and the
    // thread/context id is `params.frontend_context_uuid` (NOT top-level, the
    // pre-2026-07 read). The REAL conversation id is the RESPONSE `backend_uuid`
    // (harvested by the accumulator); these request ids are the cross-realm
    // emit-dedup key + an id-source fallback until backend_uuid arrives.
    //
    // LIVE-CONFIRMED 2026-07-18 (multi-turn recon): `backend_uuid` is PER-ASK
    // (a new uuid every turn), NOT per-thread — so it fragments one chat into N
    // sessions if used as the conversation id. A FOLLOW-UP ask (query_source
    // "followup") carries `params.last_backend_uuid` = the PREVIOUS turn's
    // backend_uuid (the thread CHAIN); the first ask (query_source "home") has
    // NO last_backend_uuid and NO frontend_context_uuid worth trusting as the
    // thread key. makePerplexityThreadResolver folds this chain (+ the /search
    // URL) into ONE stable thread id.
    const out = {
      prompt: "",
      model: "",
      conversationId: "",
      frontendUuid: "",
      lastBackendUuid: "",
    };
    if (!bodyText) return out;
    try {
      const j = JSON.parse(bodyText);
      const params = j.params && typeof j.params === "object" ? j.params : {};
      out.prompt =
        (typeof j.query_str === "string" && j.query_str) ||
        (typeof params.query_str === "string" && params.query_str) ||
        (typeof params.dsl_query === "string" && params.dsl_query) ||
        (typeof j.q === "string" && j.q) ||
        "";
      out.model =
        params.model_preference ||
        params.model ||
        j.model_preference ||
        j.model ||
        "";
      out.frontendUuid = params.frontend_uuid || j.frontend_uuid || "";
      // The thread CHAIN link: a follow-up ask's last_backend_uuid points at
      // the PREVIOUS turn's backend_uuid (absent on the first ask from home).
      out.lastBackendUuid =
        params.last_backend_uuid || j.last_backend_uuid || "";
      out.conversationId =
        params.frontend_context_uuid ||
        j.frontend_context_uuid ||
        j.context_uuid ||
        "";
    } catch {
      /* ignore */
    }
    return out;
  }

  function parseGeminiRequest(bodyText) {
    // Gemini's request is form-encoded (`f.req=<url-encoded JSON>&at=…`) — the
    // prompt is buried in a deeply-escaped RPC argument array and the model is
    // NOT in the body (it rides the `x-goog-ext-525001261-jspb` request HEADER,
    // an OPAQUE jspb array holding a session UUID, NOT a hex→model-name table —
    // there is no name table to build; the caller prefers a DOM model-picker
    // read for the model).
    //
    // LIVE-CONFIRMED 2026-07-11 (StreamGenerate capture): the form field
    // `f.req` decodes to `[null, "<inner-json-string>"]`; `JSON.parse(inner)`
    // is the RPC arg array whose `[0][0]` is the prompt text. The peel is
    // bounded and fail-soft to "" on ANY shape mismatch — Google churns these
    // array positions, and a wrong guess must degrade to an estimate, never
    // throw.
    const out = { prompt: "", model: "", conversationId: "" };
    if (!bodyText || typeof bodyText !== "string") return out;
    try {
      // Body is application/x-www-form-urlencoded; URLSearchParams applies the
      // '+' → space + percent-decode that form-encoding mandates. A literal
      // '+' inside the JSON was sent as %2B, so decoding is lossless.
      const reqRaw = new URLSearchParams(bodyText).get("f.req");
      if (!reqRaw) return out;
      const outer = JSON.parse(reqRaw);
      const innerStr =
        Array.isArray(outer) && typeof outer[1] === "string"
          ? outer[1]
          : typeof outer === "string"
          ? outer
          : "";
      if (!innerStr) return out;
      const inner = JSON.parse(innerStr);
      if (
        Array.isArray(inner) &&
        Array.isArray(inner[0]) &&
        typeof inner[0][0] === "string"
      ) {
        out.prompt = inner[0][0];
      }
    } catch {
      /* Google churns this RPC shape — fail soft to an empty prompt. */
    }
    return out;
  }

  // --- ChatGPT op-grammar helpers ------------------------------------------
  // Shared by both ChatGPT accumulators (the SSE makeChatGPTAccumulator and
  // the WebSocket makeChatGPTWSAccumulator), which read the same o/p/v op
  // grammar. Pure: no accumulator state.

  // pathIsAssistantText matches an op path that appends to the assistant
  // message body (content parts[0]).
  function pathIsAssistantText(p) {
    return typeof p === "string" && p.indexOf("content/parts/0") !== -1;
  }

  // pathIsConvId matches a delta-encoded snapshot path whose leaf is the
  // conversation id (e.g. a patch sub-op `{"p":"/conversation_id",...}`).
  function pathIsConvId(p) {
    return typeof p === "string" && /conversation_id$/.test(p);
  }

  // isHiddenChatGPTSnapshot reports whether a message snapshot is a hidden /
  // system one, which is never the answer (re-review HIGH #1, wave-5): it
  // carries weight 0.0 EVEN WHEN the explicit is_visually_hidden flag is
  // absent, or it carries metadata.is_visually_hidden_from_conversation. Such
  // a snapshot streams with a terminal status already set. The real answer is
  // weight 1.0 (fixture c289780f...). The SSE answer-container test and the
  // WS answer-target test both use this one predicate.
  function isHiddenChatGPTSnapshot(m) {
    return m.weight === 0 || !!(m.metadata && m.metadata.is_visually_hidden_from_conversation === true);
  }

  // --- ChatGPT accumulator -------------------------------------------------
  // SSE `data: {json}` frames keyed o=op / p=path / v=value. Frame shapes
  // ([high] confidence, July-2026 reverse-engineering):
  //   (1) input_message echo of the USER turn — author.role != "assistant";
  //       EXCLUDED from the response text.
  //   (2) snapshot: {"p":"","o":"add","v":{"message":{id,author,content.parts,
  //       metadata},"conversation_id":...}} — carries the assistant message id
  //       + metadata.model_slug; parts are usually empty at stream start. The
  //       very first bootstrap frame omits o/p (default op "add" at path "").
  //   (3) patch batch: {"o":"patch","p":"","v":[{"p":"/message/content/parts/0",
  //       "o":"append","v":"text"}, ...]} — v is an ARRAY of sub-ops.
  //   (4) STICKY delta: {"v":"text"} with o AND p OMITTED — inherits o/p from
  //       the PREVIOUS frame. THIS IS THE #1 SILENT-FAILURE MODE: a parser
  //       that requires o+p on every frame drops most of the streamed text.
  // Response text = concat of every `v` string appended at a path containing
  // "content/parts/0" for the assistant message. Terminated by `data:[DONE]`.
  function makeChatGPTAccumulator() {
    const state = {
      text: "",
      conversationId: "",
      messageId: "",
      model: "",
      handoff: false,
      handoffId: "", // normalized per-turn exchange id (two-leg correlator)
      // complete = the SSE answer reached a recognized END-OF-TURN signal
      // (status:"finished_successfully" / end_turn:true / metadata is_complete
      // / the `message_stream_complete` event) FOR THE ACTIVE ASSISTANT ANSWER
      // MESSAGE. The transport REQUIRES this before emitting the SSE leg
      // (re-review HIGH #1): a stream that errored or closed after harvesting
      // only PARTIAL text must NOT emit — otherwise that truncated emit lands
      // in recentEmits and SUPPRESSES the WS leg's complete answer, corrupting
      // the capture. A fully-streamed free-tier turn carries the terminal patch
      // + `message_stream_complete`, so it still emits; a contentless paid
      // handoff leg never had content anyway.
      //
      // COMPLETION IS ANSWER-SCOPED (re-review HIGH #1, deeper): the SSE feed
      // ECHOES the USER turn — and streams hidden system messages — that
      // ALREADY carry status:"finished_successfully" before the assistant even
      // begins (see the free-tier fixture: the user echo 57ad4b53… / the
      // hidden `is_visually_hidden_from_conversation` messages all carry the
      // terminal status). Accepting completion from ANY snapshot flips this
      // flag TRUE before the answer streams, so a later truncated/errored
      // answer still passes the gate and emits a partial. So completion is tied
      // ONLY to the active answer container (author role assistant, content_type
      // text / channel final, NOT hidden, NOT model_editable_context) — its id,
      // its inline flags, its `/message/...` patch flags, and the terminal
      // `message_stream_complete` once that answer has appeared.
      complete: false,
    };
    // Sticky-frame inheritance: the last resolved op/path, carried into a
    // frame that omits o and/or p.
    let curOp = "";
    let curPath = "";
    let appendedAny = false;
    let snapshotText = "";
    // Answer-message correlation (re-review HIGH #1). activeAnswerId is the id
    // of the assistant ANSWER container currently being built (a
    // message_stream_complete carrying a message id must MATCH it to count as
    // completion); curMessageIsAnswer tracks whether the LAST message snapshot
    // processed was the answer container, so path/patch-scoped completion
    // sub-ops (`/message/status`, `/message/end_turn`, …) — which carry no
    // message id and modify "the current message" — AND an id-less
    // message_stream_complete count ONLY while the answer is the current
    // message (re-review HIGH, wave-6).
    let activeAnswerId = "";
    let curMessageIsAnswer = false;

    // noteCompletion sets state.complete from any recognized end-of-answer
    // signal carried by a delta/patch sub-op: a `.../status` op valued
    // "finished_successfully", a `.../end_turn` op set true, or an
    // `is_complete` op set true (also unwrapped from a metadata OBJECT value's
    // fields). The assistant snapshot branch + the `message_stream_complete`
    // event set the flag directly. in_progress / other statuses never mark it.
    //
    // These path/patch sub-ops carry NO message id — they modify "the current
    // message". So they count ONLY while the answer container is the current
    // message (re-review HIGH #1): the terminal `/message/status` etc. patch
    // that closes the answer arrives after the answer snapshot set
    // curMessageIsAnswer, whereas the user-echo / hidden-message snapshots that
    // pre-carry finished_successfully are handled inline (and rejected) below.
    function noteCompletion(path, value) {
      if (!curMessageIsAnswer) return;
      if (typeof path === "string") {
        if (/(^|\/)status$/.test(path) && value === "finished_successfully") {
          state.complete = true;
        } else if (/(^|\/)end_turn$/.test(path) && value === true) {
          state.complete = true;
        } else if (/is_complete$/.test(path) && value === true) {
          state.complete = true;
        }
      }
      // A metadata (or status/end_turn) OBJECT patch value carries the flag on a
      // field rather than the path leaf — e.g. `{"is_complete":true}`.
      if (value && typeof value === "object" && !Array.isArray(value)) {
        if (
          value.is_complete === true ||
          value.status === "finished_successfully" ||
          value.end_turn === true
        ) {
          state.complete = true;
        }
      }
    }

    // setHandoffId records the FIRST non-empty correlator seen (like setConvId:
    // never overwrite with a later empty). Both legs harvest it so the
    // transport can pair them precisely instead of guessing.
    function setHandoffId(v) {
      if (v && !state.handoffId) state.handoffId = v;
    }

    // setConvId records the FIRST non-empty conversation id seen. A new-chat
    // thinking turn's leg 1 carries no id anywhere, so harvest is scanned from
    // MANY locations per frame (top-level, snapshot, message metadata,
    // delta-encoded `/conversation_id` patch paths, final metadata frame);
    // never overwrite a real id with a later empty one.
    function setConvId(v) {
      if (typeof v === "string" && v && !state.conversationId) {
        state.conversationId = v;
      }
    }

    // isAnswerContainer reports whether a message snapshot is the active
    // assistant ANSWER container — the one message whose content parts[0]
    // receives the harvested answer deltas and whose terminal status closes
    // the turn (re-review HIGH #1). It is:
    //   • author.role === "assistant" (never the user echo);
    //   • NOT is_visually_hidden_from_conversation (hidden system messages
    //     stream with the terminal status already set);
    //   • content_type "text" — or absent (some builds omit it) — but NEVER a
    //     non-text container like "model_editable_context" (the assistant-role
    //     context message that ALSO carries resolved_model_slug + a terminal
    //     status but is not the answer).
    // Completion + the harvested answer id are scoped to this message only; the
    // model echo is still harvested from any assistant-role message (both the
    // context and answer messages carry it) since a model string is harmless.
    function isAnswerContainer(m) {
      if (!m || !m.author || m.author.role !== "assistant") return false;
      // A hidden/system snapshot (isHiddenChatGPTSnapshot, the predicate the
      // WS accumulator shares) must NEVER be the answer container — else its
      // pre-carried finished_successfully marks completion and a later
      // truncated real answer emits partial.
      if (isHiddenChatGPTSnapshot(m)) return false;
      // When a channel field is present it MUST be "final" — the visible answer
      // message is channel:"final" (fixture). A non-final-channel assistant
      // snapshot (analysis/commentary/scratch channel) is NOT the answer, even
      // if it is weight 1.0 text. Channel absent is permitted (older builds omit
      // it) so the predicate stays additive for pre-channel wire shapes.
      if (m.channel != null && m.channel !== "final") return false;
      const ct = m.content && m.content.content_type;
      if (ct && ct !== "text") return false;
      return true;
    }

    // applyOp handles one resolved operation. Patch-batch sub-ops are routed
    // back through here with their own o/p/v.
    function applyOp(op, path, value) {
      if (Array.isArray(value)) {
        // patch batch: v is an array of sub-ops each carrying its own o/p/v.
        for (const sub of value) {
          if (!sub || typeof sub !== "object") continue;
          const so = "o" in sub ? sub.o : "append";
          const sp = "p" in sub ? sub.p : path;
          applyOp(so, sp, sub.v);
        }
        return;
      }
      noteCompletion(path, value);
      if (value && typeof value === "object" && value.message) {
        // snapshot (initial full frame or an explicit add/replace of message).
        const m = value.message;
        setConvId(value.conversation_id);
        // Message metadata also carries the id on some builds (a final
        // assistant snapshot / metadata frame) — harvest it too.
        if (m.metadata) setConvId(m.metadata.conversation_id);
        const role = m.author && m.author.role;
        // Track whether THIS snapshot is the active answer container so the
        // subsequent path/patch completion sub-ops (which modify "the current
        // message") are scoped to it (re-review HIGH #1). A non-answer snapshot
        // (user echo, hidden system message, model_editable_context) resets the
        // flag so its pre-carried finished_successfully never marks completion.
        const answer = isAnswerContainer(m);
        curMessageIsAnswer = answer;
        if (answer) {
          if (m.id) {
            state.messageId = m.id;
            activeAnswerId = m.id;
          }
          // A terminal assistant ANSWER snapshot can carry completion inline.
          // Scoped to the answer container: a user echo / hidden message that
          // pre-carries the same status must NOT flip completion.
          if (
            m.status === "finished_successfully" ||
            m.end_turn === true ||
            (m.metadata && m.metadata.is_complete === true)
          ) {
            state.complete = true;
          }
          const joined = joinParts((m.content && m.content.parts) || []);
          if (joined.length > snapshotText.length) snapshotText = joined;
        }
        if (role === "assistant") {
          // Server model echo. LIVE-CONFIRMED 2026-07-18 (free-tier inline SSE):
          // the assistant snapshot metadata carries `resolved_model_slug`
          // (observed "gpt-5-5"); the older `model_slug` + `default_model_slug`
          // spellings are kept as fallbacks. Mirror the WS accumulator's
          // harvestMessageMeta precedence so both legs resolve the same model.
          // Harvested from ANY assistant-role message (the model_editable_context
          // message carries it too) — a model string is answer-agnostic.
          const slug =
            (m.metadata &&
              (m.metadata.resolved_model_slug ||
                m.metadata.model_slug ||
                m.metadata.default_model_slug)) ||
            "";
          if (slug) state.model = slug;
        }
        // author.role != assistant → input_message echo; excluded.
        return;
      }
      if (value && typeof value === "object") {
        // A non-message object frame can still carry the id directly (a final
        // `conversation_detail_metadata`-style frame under a `v`).
        setConvId(value.conversation_id);
        return;
      }
      if (typeof value === "string" && pathIsConvId(path)) {
        // Delta-encoded snapshot path whose leaf is the conversation id.
        setConvId(value);
        return;
      }
      if (typeof value === "string" && pathIsAssistantText(path)) {
        // Scope the harvested answer text to the tracked answer container
        // (re-review HIGH #1, wave-5): a `content/parts/0` append modifies "the
        // current message", so harvest it ONLY while the answer container is the
        // current message — the SAME message the terminal completion sub-ops are
        // scoped to via noteCompletion's curMessageIsAnswer gate. A stray append
        // targeting a hidden/system or model_editable_context message (which
        // isAnswerContainer rejected → curMessageIsAnswer=false) can no longer
        // poison the answer text. This mirrors the WS accumulator's
        // activeTargetId scoping.
        if (curMessageIsAnswer) {
          state.text += value;
          appendedAny = true;
        }
      }
    }

    const reader = makeLineReader();
    function handleLine(line) {
      const t = line.trim();
      if (!t.startsWith("data:")) return;
      const payload = t.slice(5).trim();
      if (payload === "" || payload === "[DONE]") return;
      // Pro/Thinking-tier bootstrap → a SECOND-leg WebSocket. [medium]
      if (payload.indexOf("stream_handoff") !== -1) {
        state.handoff = true;
        // PARTIALLY LIVE-CONFIRMED 2026-07-10: a gpt-5-6-thinking turn's first
        // leg (POST /backend-api/f/conversation/prepare) returns
        // {"status":"ok","conduit_token":"<JWT>"} — i.e. the real completion
        // streams over a SEPARATE "conduit" second leg keyed by that token, NOT
        // this SSE response. This grounds the two-leg model. STILL UNCONFIRMED:
        // the conduit/WS transport + `encoded_item` frame shape (no second-leg
        // capture yet). Until then a handoff turn records whatever the first
        // leg carried (may be empty for a pure-thinking response).
      }
      let ev;
      try {
        ev = JSON.parse(payload);
      } catch {
        return;
      }
      // The `event: delta_encoding` marker's `data: "v1"` parses to a STRING,
      // not an object — and free-tier ChatGPT streams the answer INLINE on this
      // SSE leg PREFIXED by exactly that marker (LIVE-CONFIRMED 2026-07-18,
      // plan_type:"free" / gpt-5-5 / fast_convo). Without this guard the very
      // next `"o" in ev` test THROWS `Cannot use 'in' operator to search for 'o'
      // in v1`, aborting the whole feed on the first line so the inline answer
      // is lost (the free-tier "captures nothing" bug). Drop any non-object
      // frame (string marker / bare value / array) exactly like the WS
      // accumulator's handleEncodedEvent guard.
      if (ev === null || typeof ev !== "object" || Array.isArray(ev)) return;
      setConvId(ev.conversation_id);
      // Two-leg correlator harvest. The leg-1 `stream_handoff` frame carries
      // `turn_exchange_id` / `options[].topic_id`; the `resume_conversation_token`
      // frame (both legs) carries a JWT whose `turn_topic_id` claim is the same
      // exchange id. Harvesting it on BOTH legs lets the transport pair an
      // out-of-order resume to the RIGHT buffered leg 1 (the fix for two id-less
      // handoffs overlapping in one tab) rather than guessing newest-synthetic.
      if (ev.type === "stream_handoff") {
        setHandoffId(handoffIdFromFrame(ev));
      } else if (ev.type === "resume_conversation_token") {
        // turnTopicFromJWT is type-guarded + fail-soft (non-string /
        // malformed token yields ""), so no caller-side check is needed.
        setHandoffId(turnTopicFromJWT(ev.token));
      }
      // The terminal `message_stream_complete` event is the belt-and-braces
      // end-of-turn signal (carries no o/p/v) — it finalizes the CURRENT
      // answer. SCOPE it to the ACTIVE answer, not merely "an answer was ever
      // seen" (re-review HIGH, wave-6): gating on an ever-seen-answer flag
      // (the removed sawAnswerContainer) lets a truncated stream append PARTIAL answer
      // text, then have a TERMINAL non-answer snapshot (a
      // model_editable_context / hidden / user / weight-0 / non-final message)
      // flip curMessageIsAnswer=false, and THEN receive an id-less
      // message_stream_complete — the ever-seen flag would still fire and emit
      // that partial answer even though completion is no longer scoped to the
      // tracked answer. So:
      //   • accept the id-less event as a completion signal ONLY while
      //     curMessageIsAnswer is true (the active answer is still the current
      //     message — the SAME scope noteCompletion's patch sub-ops require);
      //   • if the event carries a message identifier, require it to MATCH
      //     activeAnswerId (a matching id is a reliable correlation even if a
      //     later non-answer snapshot flipped curMessageIsAnswer).
      // When it can't be reliably correlated to the active answer it is NOT
      // used as an independent completion signal — the confirmed free-tier
      // terminal answer PATCH (status:"finished_successfully" / end_turn:true,
      // scoped through noteCompletion) already set complete on the answer
      // MESSAGE, so a fully-streamed free-tier turn still emits. VERIFIED
      // against the free-tier fixture (chatgpt-freetier-inline-sse-2026-07-18):
      // the terminal patch precedes message_stream_complete AND no intervening
      // non-answer snapshot flips curMessageIsAnswer, so the event here is pure
      // belt-and-suspenders and the turn completes either way.
      if (ev.type === "message_stream_complete") {
        const evAnswerId =
          (typeof ev.message_id === "string" && ev.message_id) ||
          (typeof ev.id === "string" && ev.id) ||
          "";
        if (evAnswerId ? evAnswerId === activeAnswerId : curMessageIsAnswer) {
          state.complete = true;
        }
      }
      // Resolve op/path with sticky inheritance from the previous frame.
      const op = "o" in ev ? ev.o : curOp;
      const path = "p" in ev ? ev.p : curPath;
      curOp = op;
      curPath = path;
      if ("v" in ev) applyOp(op, path, ev.v);
    }

    return {
      state,
      feed(chunk) {
        for (const line of reader.push(chunk)) handleLine(line);
      },
      finalize() {
        const last = reader.flush();
        if (last) handleLine(last);
        // Short responses can arrive as a snapshot only (no appends). Fall
        // back to the snapshot text when nothing was appended.
        if (!appendedAny && snapshotText.length > state.text.length) {
          state.text = snapshotText;
        }
      },
    };
  }

  // --- ChatGPT two-leg (handoff → resume) correlation ----------------------
  // LIVE-CONFIRMED 2026-07-11: a THINKING turn splits across two SSE POSTs.
  // Leg 1 (`/backend-api/f/conversation`) carries the prompt + request model
  // but its response is ONLY a `stream_handoff` + `[DONE]` — no answer text.
  // The answer streams on leg 2, a SECOND POST to
  // `/backend-api/f/conversation/resume` (body `{conversation_id, offset:0}`)
  // carrying the classic o/p/v deltas + the `model_slug` echo + the assistant
  // message id. A NON-thinking turn streams o/p/v directly on leg 1 with NO
  // handoff. These pure helpers let the transport layer (content-main.js)
  // decide, per finalized accumulator state, whether to buffer leg 1, merge a
  // resume leg, or emit directly — WITHOUT branching on a hostname.

  // isChatGPTResumePath reports whether a request path is the resume second
  // leg (matches both the `/f/` and non-`/f/` conversation bases).
  function isChatGPTResumePath(pathname) {
    return (
      typeof pathname === "string" && /\/conversation\/resume$/.test(pathname)
    );
  }

  // (Removed: conversationIdFromChatGPTURL.) A `/conversation/<uuid>` path
  // segment is NOT a turn carrier — the turn POST is always the bare
  // `/backend-api[/f]/conversation` (+ `/resume`) base, and `isCaptureURL`
  // never admits a `/conversation/<uuid>` path, so the URL harvester was
  // unreachable. The conversation id already arrives from the request body
  // (`{conversation_id}` on the resume leg / an existing chat) and the SSE
  // frames (resume_conversation_token / snapshot / final metadata). Scratchpad
  // recon (chatgpt-wire-findings.md) does not list `/conversation/<uuid>` as a
  // carrier. Re-add a capture path + harvester ONLY if a future capture proves
  // otherwise.

  // resolveIdSource labels the PROVENANCE of a turn's conversation id so the
  // daemon + health can distinguish a real harvest from an id-less emit. The
  // caller passes the stream-harvested id, the request-derived id (body/URL),
  // and an optional override ("resume" for a merged two-leg turn). Precedence
  // matches emit's own `stream || request || ""` id resolution.
  function resolveIdSource(streamConvId, requestConvId, override) {
    if (override) return override;
    if (streamConvId) return "stream";
    if (requestConvId) return "request";
    return "none";
  }

  // deriveHealthBeacon maps a per-site health counter object to the compact
  // {status, reason, priority} the native host relays. Additive over the
  // original ok/degraded dichotomy: an EXPLICIT status (the content script's
  // idle heartbeat) is honored as-is; captures whose ids ALL failed to harvest
  // surface as "ok-degraded-id" (still capturing text, just no correlation
  // id — the daemon falls back to synthetic session keys). Backward-compatible
  // with the Go reader, which stores/prints any status string verbatim and
  // ignores unknown fields.
  //
  // PRIORITY (idle-clobber fix, MED-4): health is keyed by SITE, not by tab,
  // and JS cannot see other tabs — so an idle background ChatGPT tab's 3-min
  // heartbeat would otherwise last-writer-wins over a DIFFERENT tab that is
  // actively capturing. We tag the idle beacon `priority:"low"` and every
  // real status `priority:"normal"`. The CONTRACT the Go reader must honor:
  // a "low" beacon MUST NOT overwrite a stored "normal" record that is still
  // recent (within the idle window). Absent the Go change the field is inert
  // (unknown field, ignored) and behavior is unchanged — so it is safe to ship
  // ahead of the Go side.
  function deriveHealthBeacon(health) {
    const h = health || {};
    const captures = h.captures || 0;
    const empties = h.empties || 0;
    const idMissing = h.id_missing || 0;
    if (typeof h.status === "string" && h.status) {
      let reason = "";
      if (h.status === "idle") {
        reason =
          "no capture wire events since page load - endpoint churn or a logged-out/unmatched endpoint set";
      }
      return {
        status: h.status,
        reason,
        priority: h.status === "idle" ? "low" : "normal",
      };
    }
    if (captures === 0 && empties > 0) {
      return {
        status: "degraded",
        reason: `shape canary tripped ${empties}x with no successful capture - parser may be stale`,
        priority: "normal",
      };
    }
    if (captures > 0 && idMissing === captures) {
      return {
        status: "ok-degraded-id",
        reason: `${idMissing}/${captures} captures had no conversation_id - id harvest failing (new-chat/thinking churn); daemon uses synthetic session keys`,
        priority: "normal",
      };
    }
    return { status: "ok", reason: "", priority: "normal" };
  }

  // chatGPTIsHandoffPending reports whether a finalized leg is a thinking
  // turn's FIRST leg: a handoff was seen and no answer text arrived, so the
  // real answer is still coming on the resume leg. A leg with text (a normal
  // turn, or a resume leg) is NOT pending.
  function chatGPTIsHandoffPending(state) {
    return !!(state && state.handoff && !state.text);
  }

  // mergeChatGPTLegs folds a buffered leg-1 result (prompt + request model +
  // conversation id) with the resume leg's finalized accumulator state (answer
  // text + model_slug echo + assistant msg id) into one turn's fields. The
  // model_slug echo (leg 2) is preferred over the request model (leg 1) per
  // the ground-truth brief.
  function mergeChatGPTLegs(leg1, leg2State) {
    const a = leg1 || {};
    const b = leg2State || {};
    return {
      prompt: a.prompt || "",
      text: b.text || "",
      model: b.model || a.model || "",
      messageId: b.messageId || "",
      conversationId: b.conversationId || a.conversationId || "",
    };
  }

  // selectHandoffPending decides which buffered leg-1 (if any) a finalized
  // resume leg pairs with. PURE (the transport owns the Map + flush timers and
  // passes a plain array of pending descriptors + the resume leg's
  // {correlatorId, conversationId}); returns { entry, via } where `via` is
  // "correlator" | "conversation" | "synthetic" | "" (no match). Precedence
  // (MED-3, overlap-safe):
  //   1. correlator id — a per-turn exchange id harvested from BOTH legs'
  //      frames; unique, so it pairs the RIGHT leg even when two id-less
  //      handoffs overlap in one tab (out-of-order resume A can't steal B).
  //   2. conversation id — a non-synthetic leg-1 keyed by the same id.
  //   3. sole synthetic — ONLY when the resume is itself id-less AND exactly
  //      one synthetic (id-less) leg-1 is pending. Zero or 2+ → no match
  //      (ambiguous; the buffered legs emit alone on their flush timers).
  // A resume that carries a real conversation id NEVER falls through to the
  // synthetic rule — an unmatched real-id resume emits as-is rather than
  // raiding a synthetic entry.
  function selectHandoffPending(pending, leg2) {
    const list = Array.isArray(pending) ? pending : [];
    const corrId = (leg2 && leg2.correlatorId) || "";
    const convId = (leg2 && leg2.conversationId) || "";
    if (corrId) {
      for (const e of list) {
        if (e && e.correlatorId && e.correlatorId === corrId) {
          return { entry: e, via: "correlator" };
        }
      }
    }
    if (convId) {
      for (const e of list) {
        if (e && !e.synthetic && e.conversationId === convId) {
          return { entry: e, via: "conversation" };
        }
      }
      // Real convId but nothing matched → do NOT raid a synthetic entry.
      return { entry: null, via: "" };
    }
    // Id-less resume: adopt the sole synthetic pending, else don't guess.
    let sole = null;
    let count = 0;
    for (const e of list) {
      if (e && e.synthetic) {
        count++;
        sole = e;
      }
    }
    return count === 1 ? { entry: sole, via: "synthetic" } : { entry: null, via: "" };
  }

  // --- Claude.ai accumulator -----------------------------------------------
  // Anthropic Messages-API event model over SSE: message_start (model at
  // message.model) → content_block_start → content_block_delta (text via
  // delta.type "text_delta" → delta.text; reasoning via "thinking_delta" →
  // delta.thinking) → content_block_stop → message_delta → message_stop.
  // Response text = the text_delta.text run across every content block, in
  // stream order. thinking_delta is reasoning, NOT the visible response, so it
  // is not appended. LIVE-CONFIRMED 2026-07-10: the web stream carries NO usage
  // (no message.usage.input_tokens, no message_delta.usage.output_tokens) — the
  // usage reads below are kept only as a forward-compatible best-effort.
  function makeClaudeAccumulator() {
    const state = {
      text: "",
      conversationId: "",
      messageId: "",
      model: "",
      inputTokens: 0,
      outputTokens: 0,
    };
    const reader = makeLineReader();
    function handleLine(line) {
      const t = line.trim();
      if (!t.startsWith("data:")) return;
      const payload = t.slice(5).trim();
      if (payload === "" || payload === "[DONE]") return;
      let ev;
      try {
        ev = JSON.parse(payload);
      } catch {
        return;
      }
      if (ev.type === "content_block_delta" && ev.delta) {
        const dt = ev.delta.type;
        if (dt === "text_delta" && typeof ev.delta.text === "string") {
          state.text += ev.delta.text;
        } else if (dt === undefined && typeof ev.delta.text === "string") {
          // Defensive: an older shape without an explicit delta.type.
          state.text += ev.delta.text;
        }
        // thinking_delta (ev.delta.thinking) is intentionally ignored.
      } else if (ev.type === "message_start" && ev.message) {
        if (ev.message.id) state.messageId = ev.message.id;
        if (ev.message.model) state.model = ev.message.model;
        // LIVE-CONFIRMED 2026-07-10: the CONSUMER web /completion stream does
        // NOT expose usage — a full opus-4-8 turn carried no usage/token field
        // anywhere (message_start.usage absent; message_delta had no usage).
        // Tokens are therefore ESTIMATED (chars/4) downstream. We still read
        // usage when present so a future Anthropic change is picked up for free.
        if (
          ev.message.usage &&
          typeof ev.message.usage.input_tokens === "number"
        ) {
          state.inputTokens = ev.message.usage.input_tokens;
        }
      } else if (ev.type === "message_delta") {
        // usage.output_tokens is CUMULATIVE in message_delta — overwrite,
        // never accumulate.
        if (ev.usage && typeof ev.usage.output_tokens === "number") {
          state.outputTokens = ev.usage.output_tokens;
        }
      } else if (typeof ev.completion === "string") {
        state.text += ev.completion; // legacy single-field shape
      }
    }

    return {
      state,
      feed(chunk) {
        for (const line of reader.push(chunk)) handleLine(line);
      },
      finalize() {
        const last = reader.flush();
        if (last) handleLine(last);
      },
    };
  }

  // --- Perplexity accumulator ----------------------------------------------
  // SSE `event: message` frames + `data: {json}`, terminated by
  // `event: end_of_stream`. LIVE-CONFIRMED 2026-07-10: conversationId at
  // data.backend_uuid, messageId at data.uuid. The response text is nested
  // JSON-as-string: data.text is ITSELF a JSON string → parse → array of step
  // objects → the step with step_type=="FINAL" → its `content` (a JSON string
  // OR, on the schematized build, an object directly) → {answer, ...}. On the
  // schematized-API build the `.answer` is AGAIN a JSON string wrapper
  // (`{"answer":"…"}`), peeled by unwrapSchematizedAnswer. Decoding `text` only
  // once yields an opaque string, so a naive `data.text` read captures nothing.
  function makePerplexityAccumulator() {
    const state = { text: "", conversationId: "", messageId: "", model: "" };

    // textFromItemPayload pulls the visible answer prose out of one
    // workflow-block item payload. LIVE-CONFIRMED 2026-07-17: the answer lives
    // at item.payload.text_payload.text; index-guarded fallbacks cover sibling
    // spellings (payload.text / payload.answer) without ever throwing.
    function textFromItemPayload(payload) {
      if (!payload || typeof payload !== "object") return "";
      const tp = payload.text_payload;
      if (tp && typeof tp === "object" && typeof tp.text === "string") {
        return tp.text;
      }
      if (typeof payload.text === "string") return payload.text;
      if (typeof payload.answer === "string") return payload.answer;
      return "";
    }

    // textFromBlock extracts ONE block's answer text. LIVE-CONFIRMED 2026-07-18:
    //   * markdown_block (current build): `.answer` (a full string) OR `.chunks[]`
    //     (string parts, concatenated — streaming pieces of ONE block).
    //   * workflow_block (older 2026-07-17 build): steps[].items[]
    //     .payload.text_payload.text (concatenated within the block).
    // Returns "" on a shape mismatch (never throws).
    function textFromBlock(block) {
      const wf = block.workflow_block;
      if (wf && Array.isArray(wf.steps)) {
        let s = "";
        for (const step of wf.steps) {
          if (!step || !Array.isArray(step.items)) continue;
          for (const item of step.items) {
            if (!item || typeof item !== "object") continue;
            const t = textFromItemPayload(item.payload || item);
            if (t) s += t;
          }
        }
        if (s) return s;
      }
      const mb = block.markdown_block || block.plain_text;
      if (mb && typeof mb === "object") {
        if (typeof mb.answer === "string" && mb.answer) return mb.answer;
        if (Array.isArray(mb.chunks)) {
          let s = "";
          for (const ch of mb.chunks) if (typeof ch === "string") s += ch;
          if (s) return s;
        }
      }
      return "";
    }

    // extractFromBlocks walks the "blocks" answer shape (the FINAL-step
    // `data.text` JSON-string shape moved here — MEMORY: "answer moved to
    // blocks[]...", live-confirmed 2026-07-17/18): ev.blocks[] carries the
    // visible answer in a `markdown_block` (or older `workflow_block`). A single
    // SSE snapshot can carry MULTIPLE answer blocks — a duplicate
    // `intended_usage:"ask_text_0_markdown"` AND the canonical
    // `intended_usage:"ask_text"` (both the SAME answer) — so CONCATENATING them
    // double-counts ("100" + "100" → "100100"). Instead PREFER the canonical
    // `ask_text` block; fall back to the LONGEST single block. Perplexity streams
    // CUMULATIVE snapshots, so the caller keeps the longest extraction across
    // frames and never applies diff patches itself. Fail-soft to "" (the old
    // FINAL-step decode is the further fallback).
    function extractFromBlocks(ev) {
      if (!Array.isArray(ev.blocks)) return "";
      let preferred = "";
      let longest = "";
      for (const block of ev.blocks) {
        if (!block || typeof block !== "object") continue;
        const t = textFromBlock(block);
        if (!t) continue;
        if (block.intended_usage === "ask_text" && t.length > preferred.length) {
          preferred = t;
        }
        if (t.length > longest.length) longest = t;
      }
      return preferred || longest;
    }

    function decodeFinalAnswer(ev) {
      // NEW shape first: the visible answer in ev.blocks[].workflow_block…
      const blockAnswer = extractFromBlocks(ev);
      if (blockAnswer) return unwrapSchematizedAnswer(blockAnswer);
      if (typeof ev.text === "string") {
        let steps;
        try {
          steps = JSON.parse(ev.text);
        } catch {
          steps = null;
        }
        if (Array.isArray(steps)) {
          for (const step of steps) {
            if (!step || step.step_type !== "FINAL") continue;
            if (typeof step.content === "string") {
              try {
                const fin = JSON.parse(step.content);
                if (fin && typeof fin.answer === "string") {
                  return unwrapSchematizedAnswer(fin.answer);
                }
              } catch {
                /* fall through to other shapes */
              }
            } else if (step.content && typeof step.content === "object") {
              // Schematized-API build (LIVE-CONFIRMED 2026-07-10): FINAL.content
              // arrives as an OBJECT directly and its `.answer` is a nested
              // JSON string — unwrap it to the prose.
              if (typeof step.content.answer === "string") {
                return unwrapSchematizedAnswer(step.content.answer);
              }
            }
          }
        }
      }
      // Fallbacks (older shapes): a plain answer/text field.
      if (typeof ev.answer === "string") return unwrapSchematizedAnswer(ev.answer);
      return "";
    }

    const reader = makeLineReader();
    function handleLine(line) {
      const t = line.trim();
      if (!t.startsWith("data:")) return;
      const payload = t.slice(5).trim();
      if (payload === "" || payload === "[DONE]") return;
      let ev;
      try {
        ev = JSON.parse(payload);
      } catch {
        return;
      }
      if (ev.backend_uuid) state.conversationId = ev.backend_uuid;
      if (ev.uuid && !state.messageId) state.messageId = ev.uuid;
      // model at display_model (LIVE 2026-07-17); first non-empty wins.
      if (typeof ev.display_model === "string" && ev.display_model && !state.model) {
        state.model = ev.display_model;
      }
      // Perplexity streams cumulative snapshots — keep the longest FINAL
      // answer seen.
      const answer = decodeFinalAnswer(ev);
      if (answer && answer.length > state.text.length) state.text = answer;
    }

    return {
      state,
      feed(chunk) {
        for (const line of reader.push(chunk)) handleLine(line);
      },
      finalize() {
        const last = reader.flush();
        if (last) handleLine(last);
      },
    };
  }

  // --- Perplexity thread-id resolution (pure) ------------------------------
  // perplexityThreadIdFromPathname pulls the thread id out of a Perplexity
  // `/search/<id>` URL path. LIVE-CONFIRMED 2026-07-18 (multi-turn recon): the
  // page URL flips to `/search/<first-ask-backend_uuid>` DURING the first ask's
  // stream and STAYS there for every later turn in the thread — including after
  // a full page reload / reopen of the thread. So the pathname is the most
  // authoritative thread key we have (it outlives an in-memory chain map).
  // Returns "" for any non-/search path (a bare "/", a settings page, etc.).
  function perplexityThreadIdFromPathname(pathname) {
    if (typeof pathname !== "string") return "";
    const m = pathname.match(/^\/search\/([^/?#]+)/);
    return m ? m[1] : "";
  }

  // makePerplexityThreadResolver builds a PER-PAGE conversation-id resolver for
  // Perplexity, whose response `backend_uuid` is PER-ASK (a new uuid every
  // turn), NOT per-thread — so keying the conversation id on the turn's OWN
  // backend_uuid fragments one chat into N Observer sessions (the bug: 3 asks →
  // 3 sessions). LIVE-CONFIRMED 2026-07-18 (multi-turn recon): the THREAD id is
  // the FIRST ask's backend_uuid; the URL flips to /search/<thread> and stays,
  // and each follow-up ask chains `last_backend_uuid` = the PREVIOUS turn's
  // backend_uuid.
  //
  // resolve() picks the thread id at turn-finalization, in PRIORITY order:
  //   1. URL — the /search/<id> pathname segment (survives reload/reopen; the
  //      authoritative thread key). id_source "url".
  //   2. Chain map — used when the URL is unavailable (the emit raced the first
  //      turn's URL flip, or the caller couldn't read location). An ask carrying
  //      last_backend_uuid=L resolves to map[L] (the thread the PRIOR turn
  //      resolved to), or L ITSELF when L is unmapped (a reopen whose in-memory
  //      map died with the old page — stable WITHIN the reopened page). "chain".
  //   3. Own backend_uuid, then the request frontend ids — the unchanged legacy
  //      fallbacks. For turn 1 from home (no last_backend_uuid) this yields the
  //      turn's own backend_uuid, which IS what the URL becomes, so every path
  //      converges on the same key. "stream" / "request" / "none".
  // After resolving to thread T with own backend_uuid B, it records map[B]=T so
  // the NEXT follow-up's last_backend_uuid=B chains to T. The map is per-page
  // (created once by the caller) and bounded.
  function makePerplexityThreadResolver() {
    const chain = new Map(); // own backend_uuid -> resolved thread id
    const MAX = 512;
    function remember(backendUuid, threadId) {
      if (!backendUuid || !threadId) return;
      chain.set(backendUuid, threadId);
      // Bounded FIFO eviction — a long-lived tab must not grow unboundedly.
      while (chain.size > MAX) chain.delete(chain.keys().next().value);
    }
    return {
      // resolve takes plain data (the caller reads location.pathname impurely
      // and passes it in) and returns { conversationId, idSource }:
      //   pathname              — completion-time location.pathname (may be "").
      //   startPathname         — the /search/<id> pathname SNAPSHOT at request
      //                           interception (adversarial review r3-2). A slow
      //                           ask begun in /search/A that finishes after an
      //                           in-SPA nav to /search/B must attribute to A, so
      //                           a start-time thread id WINS; the completion-time
      //                           pathname is consulted ONLY when the request
      //                           began outside a thread (home / first ask, where
      //                           the URL only appears mid-stream).
      //   lastBackendUuid       — request params.last_backend_uuid (chain link).
      //   ownBackendUuid        — the accumulator's harvested response backend_uuid.
      //   requestConversationId — the legacy request fallback (frontend_context_uuid).
      //   frontendUuid          — the per-turn request id (last-ditch fallback).
      resolve(info) {
        const i = info || {};
        const own =
          typeof i.ownBackendUuid === "string" ? i.ownBackendUuid : "";
        let conversationId = "";
        let idSource = "none";
        const startThread = perplexityThreadIdFromPathname(i.startPathname);
        const completionThread = perplexityThreadIdFromPathname(i.pathname);
        const hasLast =
          typeof i.lastBackendUuid === "string" && !!i.lastBackendUuid;
        // The completion-time pathname is a trustworthy thread key ONLY when the
        // ask BEGAN inside a thread (startThread wins the nav race — r3-2) or is
        // a follow-up (hasLast). For a HOME / FIRST ask (no chain link, not begun
        // in a thread) the /search/<id> URL only appears mid-stream, and a user
        // who navigates to a DIFFERENT thread before completion would make the
        // completion pathname point at the WRONG thread (re-review MED). So for
        // a first ask we accept the completion pathname ONLY when it AGREES with
        // our own harvested backend_uuid (the legitimate first-ask URL-flip to
        // /search/<own>); otherwise we prefer own.
        let trustedCompletionThread = completionThread;
        if (
          !startThread &&
          !hasLast &&
          completionThread &&
          completionThread !== own
        ) {
          trustedCompletionThread = "";
        }
        const fromUrl = startThread || trustedCompletionThread;
        if (fromUrl) {
          conversationId = fromUrl;
          idSource = "url";
        } else if (hasLast) {
          const L = i.lastBackendUuid;
          conversationId = chain.get(L) || L;
          idSource = "chain";
        } else if (own) {
          conversationId = own;
          idSource = "stream";
        } else {
          conversationId =
            (typeof i.requestConversationId === "string" &&
              i.requestConversationId) ||
            (typeof i.frontendUuid === "string" && i.frontendUuid) ||
            "";
          idSource = conversationId ? "request" : "none";
        }
        // Record this turn's own backend_uuid -> resolved thread so the next
        // follow-up (last_backend_uuid = this B) chains to the same thread.
        remember(own, conversationId || own);
        return { conversationId, idSource };
      },
    };
  }

  // --- Gemini accumulator --------------------------------------------------
  // NOT SSE. The chat call is a batchexecute-style StreamGenerate RPC whose
  // response is length-prefixed JSON frames ([high] confidence, 2026):
  //   * strip the leading `)]}'` XSSI guard + surrounding whitespace;
  //   * then repeated `<length>\n<json_array>\n` frames where LENGTH is
  //     UTF-16 CODE UNITS — native JS String slicing is already UTF-16, so no
  //     byte<->code-unit conversion is needed;
  //   * each frame is an array of RPC entries; a chat entry is
  //     ["wrb.fr", <rpcid>, "<payload JSON string>", ...] — entry[2] is a JSON
  //     string → parse → part_json;
  //   * cid = part_json[1][0], rid = part_json[1][1], candidates = part_json[4];
  //     per candidate: rcid = candidate[0], done = candidate[8][0]==2,
  //     text = candidate[1][0] (fallback candidate[22][0]),
  //     reasoning = candidate[37][0][0].
  // Gemini re-sends the FULL cumulative text every frame (SNAPSHOT), so the
  // final answer is the longest text per rcid.
  // TODO(must-verify-live): confirm the candidate index layout (1 vs 22 for
  // text, 8[0]==2 done flag, 37 reasoning) against a raw StreamGenerate
  // envelope — Google churns these array positions.
  function makeGeminiAccumulator() {
    const state = { text: "", conversationId: "", messageId: "", model: "" };
    let buf = "";

    function stripXSSI(s) {
      const idx = s.indexOf(")]}'");
      if (idx !== -1) s = s.slice(idx + 4);
      return s.replace(/^\s+/, "");
    }

    // splitFrames walks the batchexecute envelope LINE BY LINE. The wire format
    // is `<length>\n<json_array>\n` repeated, but the declared length is
    // UNRELIABLE: LIVE-CONFIRMED 2026-07-18 (real StreamGenerate capture) the
    // Google-declared length (e.g. 177) disagrees with the JS code-unit length
    // of the payload (175) by a small delta, so length-based slicing cuts every
    // frame mid-string and the whole response fails to parse (the captures:0 /
    // empties++ bug). Each RPC array is emitted on ONE physical line (JSON
    // escapes any embedded newline as `\n`, never a raw newline), and the
    // accumulator buffers the WHOLE body before harvesting at finalize, so
    // splitting the complete buffer on "\n" is lossless. Pure-digit lines (the
    // length prefixes), blanks, and a stray `)]}'` XSSI guard from a
    // concatenated second envelope are skipped; any line whose first char is `[`
    // and that JSON-parses to an array is a frame. Fail-soft on every malformed
    // / partial line.
    function splitFrames(s) {
      const frames = [];
      for (const line of s.split("\n")) {
        const t = line.trim();
        if (!t || /^\d+$/.test(t)) continue; // blank or length-prefix line
        if (t.charCodeAt(0) !== 0x5b /* [ */) continue; // frames are JSON arrays
        try {
          const v = JSON.parse(t);
          if (Array.isArray(v)) frames.push(v);
        } catch {
          /* skip malformed / partial line */
        }
      }
      return frames;
    }

    function harvest(frames) {
      const byRcid = {};
      // ID latch (adversarial review r2-3): unrelated `wrb.fr` control records
      // (e.g. pj[1]=["status","complete"]) must not clobber a real answer's
      // conversation/response ids. Prefer the verified c_*/r_* contract — a
      // canonical pair latches and is never overwritten; a non-canonical pair
      // (older synthetic shapes carry cid_*/rid_*) only SEEDS the ids until a
      // canonical pair upgrades it. Once a well-formed pair is set, a later
      // NON-canonical record is rejected, so trailing control records can't win.
      let idsSet = false; // any well-formed [cid, rid] pair latched
      let idsCanonical = false; // a verified c_*/r_* pair latched
      for (const frame of frames) {
        if (!Array.isArray(frame)) continue;
        for (const entry of frame) {
          if (!Array.isArray(entry) || entry[0] !== "wrb.fr") continue;
          const payloadStr = entry[2];
          if (typeof payloadStr !== "string") continue;
          let pj;
          try {
            pj = JSON.parse(payloadStr);
          } catch {
            continue;
          }
          if (
            Array.isArray(pj[1]) &&
            typeof pj[1][0] === "string" &&
            pj[1][0] &&
            typeof pj[1][1] === "string" &&
            pj[1][1]
          ) {
            const cid = pj[1][0];
            const rid = pj[1][1];
            const canonical = cid.charAt(0) === "c" && cid.charAt(1) === "_" &&
              rid.charAt(0) === "r" && rid.charAt(1) === "_";
            if (canonical ? !idsCanonical : !idsSet) {
              state.conversationId = cid;
              state.messageId = rid;
              idsSet = true;
              if (canonical) idsCanonical = true;
            }
          }
          const candidates = pj[4];
          if (!Array.isArray(candidates)) continue;
          // Harvest the DISPLAYED candidate only — index 0 (the verified path
          // inner[4][0][1][0]). Iterating EVERY candidate and keeping the
          // longest recorded a non-displayed alternative whenever an alt
          // candidate's text ran longer than the shown one (adversarial review
          // r2-2). Gemini re-sends the full cumulative answer per frame
          // (snapshot), so keep the longest text seen for candidate 0's rcid.
          const cand = candidates[0];
          if (!Array.isArray(cand)) continue;
          const rcid = cand[0] || "_";
          let text = "";
          if (Array.isArray(cand[1]) && typeof cand[1][0] === "string") {
            text = cand[1][0];
          } else if (Array.isArray(cand[22]) && typeof cand[22][0] === "string") {
            text = cand[22][0];
          }
          if (text) byRcid[rcid] = text; // snapshot: latest wins per rcid.
        }
      }
      let best = "";
      for (const k in byRcid) {
        if (byRcid[k].length > best.length) best = byRcid[k];
      }
      if (best) state.text = best;
    }

    return {
      state,
      feed(chunk) {
        buf += chunk;
      },
      finalize() {
        try {
          harvest(splitFrames(stripXSSI(buf)));
        } catch {
          // TODO(must-verify-live): if the structured decode yields nothing on
          // a real capture, the frame layout or candidate indices shifted —
          // re-confirm against a raw StreamGenerate envelope.
        }
      },
    };
  }

  // --- Copilot (copilot.microsoft.com) WebSocket parser --------------------
  // LIVE-CONFIRMED 2026-07-18 (copilot recon, logged-in profile, one real turn):
  // the WHOLE transport is a WebSocket — `wss://copilot.microsoft.com/c/api/chat`.
  // The client `send` frame carries the prompt as a content-PARTS ARRAY, and the
  // server streams single-JSON-object frames discriminated by `event`:
  //   send (client) → received (echo of the USER message) → startMessage (the
  //   ASSISTANT message) → appendText×N → citation/generatingCard/partCompleted
  //   → done → titleUpdate.
  // Pure half (no DOM / no WebSocket): content-main.js owns the socket patch +
  // send-frame intervention and feeds already-JSON.parsed frames to these.

  // copilotJoinContent flattens a Copilot `send`-frame `content` field into a
  // single prompt STRING. The live wire shape is a parts array
  // (`[{type:"text",text:"…"}]`); concatenate the `text` of every `{type:"text"}`
  // part (newline-joined), ignoring non-text parts (e.g. images). A plain-string
  // `content` (older/alternate builds) passes through unchanged. ALWAYS returns
  // a string — the daemon's browserchat.Parse unmarshals prompt_text into a Go
  // `string`, so an array here is the ingest-blocking bug this fixes.
  // copilotPartText returns a part's text when it is a `{type:"text"|undefined,
  // text:string}` part, else null (a non-text part — image/attachment). The
  // single shared predicate every Copilot content-shape walk consults.
  function copilotPartText(part) {
    if (
      part &&
      typeof part === "object" &&
      (part.type === "text" || part.type === undefined) &&
      typeof part.text === "string"
    ) {
      return part.text;
    }
    return null;
  }

  // copilotCollectPart captures ONE array element's text under EXACTLY the reach
  // of rewriteCopilotPart (round-4 re-review MED): an accepted
  // {type:"text"|undefined,text:string} part contributes its text; ANYTHING else
  // — a bare string, a non-text part ({type:"image",text:"SECRET"}), or a nested
  // container ({content:[…]}) — contributes NOTHING, because rewriteCopilotPart
  // leaves each of those verbatim (UNREDACTED). Capturing what the redactor
  // cannot reach would put content on the wire that redact mode never scrubs, so
  // the collector's acceptance must be co-extensive with the redactor's.
  function copilotCollectPart(part, acc) {
    if (acc.stopped) return;
    if (++acc.nodes > MAX_COERCE_PARTS) {
      acc.stopped = true;
      return;
    }
    const t = copilotPartText(part);
    if (t !== null) coercePushFragment(t, acc);
  }

  // copilotCollect flattens a Copilot `send`-frame content value into text
  // fragments whose acceptance is EXACTLY co-extensive with rewriteCopilotContent
  // (round-4 re-review MED). The prior version reused the GENERIC recursive walk,
  // which accepted MORE than the redactor could rewrite: a bare string inside an
  // array (`["SECRET"]`) and a doubly-nested container
  // (`{content:[{content:[{type:"text",text:"SECRET"}]}]}`) were both CAPTURED
  // here yet left UNREDACTED by rewriteCopilotContent — so in redact mode that
  // SECRET shipped upstream verbatim. rewriteCopilotContent redacts only: a
  // top-level string; each ACCEPTED part of a top-level array; a single
  // top-level accepted part object; or each accepted part ONE level down inside a
  // {content:[…]} / {parts:[…]} container. It does NOT redact bare strings inside
  // an array and does NOT descend into nested containers. This collector mirrors
  // that reach precisely and NEVER recurses past one level of parts (via
  // copilotCollectPart), so anything the redactor can't rewrite is never
  // captured. The MAX_COERCE_PARTS node budget still bounds a hostile huge array
  // (re-review HIGH #2) — a million non-text parts can't pin the CPU.
  function copilotCollect(content, acc) {
    if (acc.stopped) return;
    if (++acc.nodes > MAX_COERCE_PARTS) {
      acc.stopped = true;
      return;
    }
    if (typeof content === "string") {
      coercePushFragment(content, acc);
      return;
    }
    if (Array.isArray(content)) {
      for (const part of content) {
        if (acc.stopped) return;
        copilotCollectPart(part, acc);
      }
      return;
    }
    if (content && typeof content === "object") {
      // A single accepted part object → its text (mirrors rewriteCopilotContent
      // rewriting a single-object content in place).
      const t = copilotPartText(content);
      if (t !== null) {
        coercePushFragment(t, acc);
        return;
      }
      // A container object → each accepted part ONE level down, no deeper (the
      // redactor maps content.content/content.parts through rewriteCopilotPart,
      // which does not recurse into nested containers).
      if (Array.isArray(content.content)) {
        for (const part of content.content) {
          if (acc.stopped) return;
          copilotCollectPart(part, acc);
        }
        return;
      }
      if (Array.isArray(content.parts)) {
        for (const part of content.parts) {
          if (acc.stopped) return;
          copilotCollectPart(part, acc);
        }
        return;
      }
    }
    // number / bool / null / bare object / non-container: dropped — the redactor
    // returns each of these unchanged, so there is nothing redactable to capture.
  }

  // copilotJoinContent flattens the Copilot `send`-frame content into one prompt
  // STRING through the BOUNDED copilotCollect walk (re-review HIGH #2 keeps the
  // walk depth/node/byte bounded; MED #3 keeps the part predicate EXACTLY
  // copilotPartText's, so the join and rewriteCopilotContent agree on which
  // parts are text). Shape coverage matches rewriteCopilotContent: plain-string
  // passthrough / array of `{type:"text"|undefined,text}` parts joined with "\n"
  // / a single part object / a nested `{content:[…]}`|`{parts:[…]}` container.
  // A non-text part (e.g. {type:"image",text}) is dropped from the prompt — the
  // same part rewriteCopilotContent leaves structurally in place but unredacted,
  // so it must never leak into the captured prompt either.
  function copilotJoinContent(content) {
    const acc = { texts: [], bytes: 0, nodes: 0, stopped: false };
    copilotCollect(content, acc);
    return acc.texts.join("\n");
  }

  // rewriteCopilotContent returns a redacted COPY of a Copilot send-frame
  // `content` value that PRESERVES structure (adversarial review r5-3): every
  // part keeps its ORIGINAL position + metadata, only text FIELDS are replaced
  // by redact(text). Mirrors copilotJoinContent's shape coverage (string /
  // array / single object / nested parts container) so a multimodal
  // [image, text, image] keeps its ordering AND its non-text parts survive
  // untouched — the pre-fix path re-wrapped to [redacted-text, …nonText], which
  // moved the text to the front, collapsed multiple text parts into one, and
  // discarded the original text part's metadata. `redact` is (string)->string.
  function rewriteCopilotPart(part, redact) {
    const t = copilotPartText(part);
    if (t === null) return part; // non-text part: preserve verbatim (position + metadata)
    return { ...part, text: redact(t) }; // in place: keep type/partId/etc, swap text only
  }

  function rewriteCopilotContent(content, redact) {
    if (typeof content === "string") return redact(content);
    if (Array.isArray(content)) {
      return content.map((part) => rewriteCopilotPart(part, redact));
    }
    if (content && typeof content === "object") {
      if (copilotPartText(content) !== null) {
        return rewriteCopilotPart(content, redact);
      }
      if (Array.isArray(content.content)) {
        return { ...content, content: content.content.map((p) => rewriteCopilotPart(p, redact)) };
      }
      if (Array.isArray(content.parts)) {
        return { ...content, parts: content.parts.map((p) => rewriteCopilotPart(p, redact)) };
      }
    }
    return content;
  }

  // parseCopilotSendFrame extracts the outbound prompt + model + conversation id
  // from a Copilot client `send` frame (already JSON-parsed + array-unwrapped by
  // content-main). Returns { prompt, model, conversationId } — all strings.
  // `mode` ("smart" on the live wire) is the ONLY model-ish signal Copilot puts
  // on the wire; it is passed through verbatim (empty stays empty — never invent
  // a model name; the Go rule fills a default when absent).
  function parseCopilotSendFrame(frame) {
    if (!frame || typeof frame !== "object") {
      return { prompt: "", model: "", conversationId: "" };
    }
    const rawContent =
      frame.content !== undefined
        ? frame.content
        : frame.text !== undefined
          ? frame.text
          : frame.message;
    return {
      prompt: copilotJoinContent(rawContent),
      model: typeof frame.mode === "string" ? frame.mode : "",
      conversationId:
        typeof frame.conversationId === "string" ? frame.conversationId : "",
    };
  }

  // copilotTurnDisposition owns the DROP-OVER-CORRUPT policy for a new Copilot
  // turn (re-review HIGH #2). It is the single, testable place the tradeoff
  // below lives; the transport (content-main beginTurn) calls it with the PRIOR
  // not-yet-emitted turn's state and acts on the result.
  //
  // DELIBERATE TRADEOFF — the Copilot wire has NO per-generation correlator.
  // parseCopilotSendFrame harvests only conversationId / content / mode from the
  // client `send`; the server `received` frame carries a USER-echo message id
  // and `startMessage` an ASSISTANT message id — NEITHER is shared with the send,
  // and within one conversation every turn reuses the same conversationId. So a
  // turn cannot PROVE that an inbound assistant frame is its own rather than a
  // prior turn's delayed straggler, and ARRIVAL ORDER is not a sound proxy: the
  // prior wave latched frames by whichever `received` was seen first, which
  // mis-attributes when turn A's frames arrive AFTER turn B's own `received`
  // (A's answer would emit under B's prompt). Because the wire cannot
  // disambiguate, a CONTESTED turn is DROPPED, never guessed — a deliberate
  // missed capture is preferred over a corrupted (mis-paired prompt/answer) one.
  //
  // Decision, from the PRIOR turn's state:
  //   • prior emitted / absent → clean sequence, nothing to carry.
  //   • prior latched an assistant id (a CLEAN interrupt — user stopped or
  //     regenerated after the answer id was known) → QUARANTINE that id so its
  //     stragglers are dropped by messageId; the new turn is NOT contested.
  //   • else prior only saw its `received` echo (the RECEIVED-ONLY window) → its
  //     foreign frames are inbound with an id we NEVER learned (nothing to
  //     quarantine) → the new turn is CONTESTED and MUST DROP.
  // Returns { quarantineId, contested }. Pure — no I/O; no wire types leak out.
  function copilotTurnDisposition(prior) {
    const p = prior || {};
    if (p.emitted) return { quarantineId: "", contested: false };
    if (p.latchedId) return { quarantineId: p.latchedId, contested: false };
    if (p.sawReceived) return { quarantineId: "", contested: true };
    return { quarantineId: "", contested: false };
  }

  // copilotShouldEmit gates the single per-turn emit: a turn emits ONLY when it
  // reached its OWN `done`, has not already emitted, is NOT contested, and its
  // socket is NOT tainted. The contested drop is the drop-over-corrupt tradeoff
  // above — a turn begun while a prior turn's unattributable frames are still
  // inbound never emits. The `tainted` drop is the STICKY per-socket escalation
  // (re-review HIGH #2, wave-5): once ANY turn on the socket was contested, ALL
  // later turns drop too (see copilotTaintNext) — even a turn that LOOKS
  // uncontested because the prior contested turn happened to latch an
  // (unreliable, possibly foreign) id.
  function copilotShouldEmit(turn) {
    const t = turn || {};
    return !!t.done && !t.emitted && !t.contested && !t.tainted;
  }

  // copilotTaintNext folds the per-SOCKET STICKY taint (re-review HIGH #2,
  // wave-5). The wave-4 recovery was UNSOUND: a contested turn B could still
  // latch an id (its own `received` arrives, then a straggler `startMessage`
  // latches), and copilotTurnDisposition then read that latched id on turn C's
  // begin as a CLEAN interrupt → C uncontested → C emits → B's OTHER late
  // frames (a different, un-quarantined id) fold into C as {prompt:C,
  // text:answerB}. The definitive close: taint is STICKY. Once ANY turn is
  // contested (received-only interruption), the socket is DROP-ONLY for every
  // subsequent turn until a real RESYNC boundary — a socket reconnect/reset,
  // which builds a FRESH tap whose taint starts false (the ONLY way it clears).
  // A latched id from a contested/tainted accumulator may be quarantined
  // (copilotTurnDisposition.quarantineId) but MUST NOT clear the taint or mark a
  // clean interrupt. Deliberate drop-over-corrupt tradeoff: the Copilot wire has
  // no per-generation correlator (verified — attribution rests only on the
  // per-message id, which a received-only interruption never revealed), so a
  // missed capture on a tainted socket beats cross-turn corruption. Pure so the
  // transport (content-main.js, per-socket `socketTainted`) and the tests fold
  // the taint through the SAME transition.
  function copilotTaintNext(prevTainted, disp) {
    return !!prevTainted || !!(disp && disp.contested);
  }

  // makeCopilotAccumulator folds the Copilot server frame stream into a turn.
  // feed() takes ONE already-JSON.parsed server frame; state carries the
  // assembled answer + ids + title. message_id prefers the ASSISTANT message id
  // from `startMessage`, falling back to the `received` echo id only when
  // startMessage never arrives. conversationId / model / title are captured
  // belt-and-braces from whichever frame carries them (never clobbered to empty).
  function makeCopilotAccumulator(opts) {
    // deferLatchUntilReceived (re-review HIGH #2): when the transport creates
    // this accumulator to REPLACE a prior turn that was interrupted after its
    // `received` echo but before ANY assistant id latched, a stale foreign
    // `startMessage`/`appendText` for that orphan turn is still inbound and
    // must NOT latch — and contaminate — this fresh turn. In that contested
    // context the transport passes true, and the accumulator refuses to latch
    // (and drops any appendText/done) until it has seen ITS OWN `received`
    // echo — the server always echoes the user turn before streaming the
    // assistant answer, so a frame arriving before this turn's own received is
    // a straggler. Default false keeps the isolated-accumulator contract (all
    // pre-existing tests feed startMessage-first) unchanged.
    const deferLatchUntilReceived = !!(opts && opts.deferLatchUntilReceived);
    const state = {
      text: "",
      conversationId: "",
      messageId: "",
      model: "",
      title: "",
      done: false,
    };
    // startMessage is authoritative for the assistant messageId; `received`
    // (the USER-message echo) is only a fallback until it arrives.
    let sawStartMessage = false;
    // sawReceived = this turn saw its OWN `received` user echo. Gates latching
    // in deferLatchUntilReceived mode; also lets the transport detect the
    // received-only interruption window (a prior turn that saw a received but
    // never latched an assistant id).
    let sawReceived = false;
    // answerMsgId = the id the ANSWER text belongs to (the append/done scope
    // latch, adversarial review r5-1). Latched by the FIRST authoritative
    // signal: a non-empty `startMessage` messageId (preferred), else the first
    // identified `appendText`. Distinct from state.messageId (which may hold the
    // `received`/user-echo fallback). Once latched, appendText/done are accepted
    // ONLY when their messageId matches — a foreign suggestion/intervention
    // stream's id-less or foreign frames can neither contaminate the answer nor
    // terminate it. When NEVER latched (fully id-less single stream), frames are
    // accepted as-is (no id to match against).
    let answerMsgId = "";
    let answerLatched = false;
    // frozen after this turn's matching `done` — later frames (a foreign `done`,
    // a trailing suggestion stream) can no longer mutate the answer/ids.
    let frozen = false;
    function latchAnswer(id) {
      answerMsgId = id;
      answerLatched = true;
    }
    return {
      state,
      feed(frame) {
        if (!frame || typeof frame !== "object") return;
        const ev = frame.event || frame.type;
        // First-wins (adversarial review r5-2): once a turn has established its
        // conversation id (from the send frame or its own first server frame), a
        // LATE frame from a DIFFERENT (just-completed) turn must not clobber it.
        // (`titleUpdate` is exempt from the freeze below because it arrives AFTER
        // `done` on the live wire and is cosmetic-only metadata.)
        if (
          typeof frame.conversationId === "string" &&
          frame.conversationId &&
          !state.conversationId &&
          !frozen
        ) {
          state.conversationId = frame.conversationId;
        }
        switch (ev) {
          case "startMessage":
            // Truthiness (not just typeof) so an empty-string messageId can't
            // latch away the `received` fallback. Latch the FIRST assistant id
            // only — a SECOND startMessage (a foreign/suggestion message) must
            // NOT replace the authoritative id (r5-1). In deferLatch mode, wait
            // for this turn's OWN `received` before latching so an orphan turn's
            // stale startMessage can't latch the fresh accumulator (HIGH #2).
            if (
              !frozen &&
              frame.messageId &&
              typeof frame.messageId === "string" &&
              !answerLatched &&
              (!deferLatchUntilReceived || sawReceived)
            ) {
              state.messageId = frame.messageId;
              sawStartMessage = true;
              latchAnswer(frame.messageId);
            }
            break;
          case "received":
            sawReceived = true;
            if (!frozen && !sawStartMessage && typeof frame.messageId === "string") {
              state.messageId = frame.messageId; // fallback until startMessage
            }
            break;
          case "appendText":
            if (frozen || typeof frame.text !== "string") break;
            if (answerLatched) {
              // Scoped to the answer message: reject id-less AND foreign frames
              // once the assistant id is known (r5-1).
              if (frame.messageId === answerMsgId) state.text += frame.text;
            } else if (deferLatchUntilReceived && !sawReceived) {
              // deferLatch guard (HIGH #2): before this turn's own `received`,
              // any appendText is an orphan straggler — neither latch nor append.
              break;
            } else {
              // No startMessage yet. The first IDENTIFIED appendText latches the
              // answer scope to its own id (so a subsequent foreign id can't
              // contaminate) AND promotes state.messageId to that assistant id
              // (HIGH #2 (b): the done-path must remember the ASSISTANT id, not
              // the stale `received` user id); a fully id-less stream stays
              // unlatched and appends.
              if (frame.messageId && typeof frame.messageId === "string") {
                latchAnswer(frame.messageId);
                state.messageId = frame.messageId;
              }
              state.text += frame.text;
            }
            break;
          case "setOptions":
            // Not seen on the 2026-07-18 wire, but tolerated: an explicit model.
            if (typeof frame.model === "string" && frame.model) {
              state.model = frame.model;
            }
            break;
          case "titleUpdate":
            if (typeof frame.title === "string") state.title = frame.title;
            break;
          case "done":
            // Terminate on THIS turn's `done` only: a foreign `done` (different
            // messageId) must not close the accumulator (r5-1). Once the answer
            // id is latched, require an EXACT non-empty messageId match — an
            // ID-LESS `done` (an unrelated intervention/suggestion stream's
            // terminator) must NOT freeze + prematurely emit the latched answer
            // and then discard its remaining legit text (re-review MED). A
            // `done` is still accepted with NO id ONLY when the stream was never
            // latched (id-less single stream — the received-fallback path with
            // no startMessage). In deferLatch mode, an orphan turn's `done`
            // arriving before this turn's own `received` must NOT terminate it
            // (HIGH #2).
            if (deferLatchUntilReceived && !sawReceived) break;
            if (
              !frozen &&
              (!answerLatched || frame.messageId === answerMsgId)
            ) {
              state.done = true;
              frozen = true; // seal answer/id mutations — ignore trailing frames
            }
            break;
          default:
            break;
        }
      },
      // latchedAnswerId returns the answer-scoped assistant message id once it
      // is latched (from `startMessage`, else the first identified
      // `appendText`), otherwise "". The transport uses it to QUARANTINE an
      // INTERRUPTED turn's id: when a new `send` discards this accumulator
      // before its `done` (user stopped/regenerated), the abandoned turn's
      // latched id must go into the prior-id set so its late stragglers are
      // skipped and can't latch — and contaminate — the fresh turn (re-review
      // HIGH). state.messageId is NOT a safe substitute: it can hold the
      // `received`/user-echo fallback id rather than the assistant answer id.
      latchedAnswerId() {
        return answerLatched ? answerMsgId : "";
      },
      // sawReceivedEcho reports whether this turn saw its own `received` user
      // echo. The transport reads it at beginTurn to detect the RECEIVED-ONLY
      // interruption window: a prior turn that got its user echo but was cut
      // before ANY assistant id latched (latchedAnswerId() === "") — meaning a
      // foreign startMessage/appendText for it is still inbound, so the fresh
      // accumulator must be created with deferLatchUntilReceived (HIGH #2 (c)).
      sawReceivedEcho() {
        return sawReceived;
      },
    };
  }

  // --- ChatGPT WebSocket answer accumulator --------------------------------
  // GROUNDED 2026-07-17 (live logged-in CDP recon): a ChatGPT thinking turn's
  // ANSWER no longer streams over a `/backend-api/f/conversation/resume` POST
  // (the obsolete two-leg model). The leg-1 POST `/f/conversation` returns a
  // PURE `stream_handoff` (resume_conversation_token + stream_handoff, NO answer
  // text) and never cleanly closes; the ANSWER streams over the pre-existing
  // GLOBAL WebSocket `wss://ws.chatgpt.com/.../user/user-<id>` opened at page
  // load, on topic `conversation-turn-<turn_id>`. This accumulator parses those
  // WS TEXT frames. It is the WS-PRIMARY emitter for chatgpt-web; the fetch/SSE
  // leg is kept only for pre-send prompt redaction (two transports, one turn —
  // see content-main's SITE row + wsAnswer tap).
  //
  // A WS text frame is a JSON ARRAY of message objects:
  //   [{type:"message", topic_id:"conversation-turn-<TURN>",
  //     payload:{type:"conversation-turn-stream",
  //       payload:{type:"stream-item", conversation_id, turn_id,
  //                encoded_item:"<NESTED SSE STRING>"}}}]
  // `encoded_item` is itself an SSE mini-stream ("event: X\ndata: {json}\n\n")
  // carrying the SAME o/p/v delta grammar as the classic ChatGPT SSE leg. We
  // unwrap it, apply the ops (sticky o/p inheritance included), and harvest:
  //   * prompt    — the `input_message` echo (author.role user) OR a role:user
  //                 message "add" — from content.parts.
  //   * text      — assistant `content/parts/0` append ops (the visible answer).
  //   * model     — metadata.resolved_model_slug (e.g. "gpt-5-6-thinking").
  //   * messageId — the stream-item `turn_id` (NOT the inner message id).
  //   * done      — the `payload.payload.type === "done"` frame; the
  //                 topic:"conversations" `conversation-turn-complete` frame is
  //                 a belt-and-braces secondary completion signal.
  // Frames can also arrive inside a `reply.catchups[]` array (subscribe
  // recovery) — walked identically. Hidden/system weight-0 messages
  // (is_visually_hidden_from_conversation) and non-text assistant content types
  // (reasoning_recap / model_editable_context) are NOT the answer and skipped —
  // enforced by the active-append-target tracking, not merely by role.
  //
  // SINGLE-TURN scoped: the global socket multiplexes sequential/overlapping
  // turns, so the transport (content-main's wsAnswer tap) keeps a Map of these
  // accumulators keyed by topic_id (== turn_id) and routes each frame via
  // chatGPTWSFrameRoute — one independent accumulator per turn. This function
  // never has to reason about more than its own turn.
  function makeChatGPTWSAccumulator() {
    const state = {
      text: "",
      prompt: "",
      conversationId: "",
      messageId: "",
      model: "",
      done: false,
      // Cross-transport dedup ids (2026-07-17 round-2 review). A turn carries
      // TWO turn-scoped ids on the WS wire: the topic/turn id (== messageId,
      // e.g. e6a02413…) which also appears as stream_handoff.turn_exchange_id
      // and the resume_conversation_token JWT turn_topic_id; AND the
      // working_turn_id (e.g. bf89e158…) in message/input_message metadata. The
      // leg-1 SSE body was NOT capturable, so we cannot be 100% sure WHICH of
      // these the SSE accumulator's handoffId holds — so we harvest BOTH and the
      // transport dedups on EITHER (belt-and-braces).
      handoffId: "", // == the topic/turn exchange id (stream_handoff / JWT)
      workingTurnId: "", // == metadata.working_turn_id
    };
    // Sticky o/p inheritance across encoded_items (a frame that omits o and/or
    // p inherits the previous frame's — the #1 silent-failure mode).
    let curOp = "";
    let curPath = "";
    let appendedAny = false;
    let snapshotText = "";
    // activeTargetId = the id of the message that `content/parts/N` append ops
    // currently target (the last-added message). It is set ONLY to a VISIBLE
    // ASSISTANT text message, and reset to null whenever a non-answer message
    // (user / system / hidden weight-0 / non-text assistant) becomes current.
    // Appends contribute to the answer text ONLY while a visible-assistant
    // target is active — so a hidden/system snapshot followed by parts/0 appends
    // cannot pollute the answer (MED fix, 2026-07-17 adversarial review).
    let activeTargetId = null;

    function setConvId(v) {
      if (typeof v === "string" && v && !state.conversationId) state.conversationId = v;
    }
    function setModel(v) {
      if (typeof v === "string" && v && !state.model) state.model = v;
    }
    function setPrompt(v) {
      if (typeof v === "string" && v && !state.prompt) state.prompt = v;
    }
    function setHandoffId(v) {
      if (typeof v === "string" && v && !state.handoffId) state.handoffId = v;
    }
    function setWorkingTurnId(v) {
      if (typeof v === "string" && v && !state.workingTurnId) state.workingTurnId = v;
    }
    function harvestMessageMeta(m) {
      const meta = m && m.metadata;
      if (!meta) return;
      setModel(meta.resolved_model_slug || meta.model_slug || meta.default_model_slug || "");
      setConvId(meta.conversation_id);
      // working_turn_id is the SECOND turn-scoped dedup id (see state comment).
      setWorkingTurnId(meta.working_turn_id);
    }

    // applyOp mirrors the classic ChatGPT SSE op grammar (patch batch → sub-ops;
    // message snapshot add/replace; sticky string appends), extended to harvest
    // the user prompt and to ignore non-text assistant content types.
    function applyOp(op, path, value) {
      if (Array.isArray(value)) {
        // patch batch: v is an array of sub-ops each carrying its own o/p/v.
        for (const sub of value) {
          if (!sub || typeof sub !== "object") continue;
          const so = "o" in sub ? sub.o : "append";
          const sp = "p" in sub ? sub.p : path;
          applyOp(so, sp, sub.v);
        }
        return;
      }
      if (value && typeof value === "object" && value.message) {
        const m = value.message;
        setConvId(value.conversation_id);
        harvestMessageMeta(m);
        const role = m.author && m.author.role;
        if (role === "user") {
          // The user turn echo — harvest the PROMPT (never appended to text).
          if (m.content && Array.isArray(m.content.parts)) {
            const p = joinParts(m.content.parts).trim();
            if (p) setPrompt(p);
          }
          activeTargetId = null; // a user message is never an append target
          return;
        }
        // A message is the VISIBLE ANSWER target only when it is an assistant
        // TEXT message that is NOT hidden and NOT weight-0. A hidden weight-0
        // assistant snapshot, a system message, or a non-text assistant message
        // (reasoning_recap / model_editable_context) is NOT the answer.
        const hidden = isHiddenChatGPTSnapshot(m);
        const ctype = m.content && m.content.content_type;
        if (role === "assistant" && !hidden && ctype === "text") {
          activeTargetId = m.id || "__asst__";
          if (m.content && Array.isArray(m.content.parts)) {
            const joined = joinParts(m.content.parts);
            if (joined.length > snapshotText.length) snapshotText = joined;
          }
          return;
        }
        // Any other message becomes the current message but is NOT an answer
        // target — subsequent parts/0 appends (which target the current
        // message) must not be counted while it is active.
        activeTargetId = null;
        return;
      }
      if (value && typeof value === "object") {
        setConvId(value.conversation_id);
        return;
      }
      if (typeof value === "string" && pathIsConvId(path)) {
        setConvId(value);
        return;
      }
      if (typeof value === "string" && pathIsAssistantText(path)) {
        // Contribute ONLY when a visible-assistant message is the active append
        // target (MED fix): an append while a hidden/system/unset message is
        // current is not answer text.
        if (!activeTargetId) return;
        state.text += value;
        appendedAny = true;
        // Record the referenced path so a following bare {"v":"…"} continuation
        // (o AND p omitted — the delta_encoding v1 shorthand) appends to the
        // SAME part even when this append arrived inside a patch batch.
        curPath = path;
      }
    }

    function handleEncodedEvent(ev) {
      // `data: "v1"` (delta_encoding marker) parses to a STRING — the object
      // guard drops it (a bare string would also throw on the `"o" in ev` test).
      if (ev === null || typeof ev !== "object" || Array.isArray(ev)) return;
      setConvId(ev.conversation_id);
      if (ev.type === "input_message" && ev.input_message) {
        const im = ev.input_message;
        if (
          im.author &&
          im.author.role === "user" &&
          im.content &&
          Array.isArray(im.content.parts)
        ) {
          const p = joinParts(im.content.parts).trim();
          if (p) setPrompt(p);
        }
        if (im.metadata) {
          setModel(im.metadata.resolved_model_slug || "");
          setWorkingTurnId(im.metadata.working_turn_id); // 2nd dedup id
        }
        return;
      }
      // The resume_conversation_token JWT + stream_handoff carry the SAME
      // turn-exchange/topic id the SSE leg's handoff frame carries — harvest it
      // as the primary cross-transport dedup id.
      if (ev.type === "resume_conversation_token") {
        setHandoffId(turnTopicFromJWT(ev.token));
        return;
      }
      if (ev.type === "stream_handoff") {
        setHandoffId(handoffIdFromFrame(ev));
        return;
      }
      // Pure metadata frames carry no o/p/v answer content (convId already
      // harvested above). Returning early leaves the sticky o/p untouched.
      if (
        ev.type === "title_generation" ||
        ev.type === "message_marker" ||
        ev.type === "server_ste_metadata" ||
        ev.type === "message_stream_complete" ||
        ev.type === "conversation_detail_metadata"
      ) {
        return;
      }
      const op = "o" in ev ? ev.o : curOp;
      const path = "p" in ev ? ev.p : curPath;
      curOp = op;
      curPath = path;
      if ("v" in ev) applyOp(op, path, ev.v);
    }

    // feedEncodedItem parses one encoded_item SSE mini-stream. Only `data:`
    // lines carry content; `event:` lines (delta / delta_encoding) and blanks
    // are skipped. `data: [DONE]` is a stream sentinel — the REAL completion is
    // the `done` frame TYPE (handled in processMessageObj), not this line.
    function feedEncodedItem(s) {
      if (typeof s !== "string" || !s) return;
      const lines = s.split("\n");
      for (const raw of lines) {
        const t = raw.trim();
        if (!t.startsWith("data:")) continue;
        const payload = t.slice(5).trim();
        if (payload === "" || payload === "[DONE]") continue;
        let ev;
        try {
          ev = JSON.parse(payload);
        } catch {
          continue;
        }
        handleEncodedEvent(ev);
      }
    }

    function processMessageObj(msg) {
      if (!msg || msg.type !== "message" || !msg.payload) return;
      const p = msg.payload;
      if (p.type === "conversation-turn-complete") {
        // Secondary belt-and-braces completion on the "conversations" topic.
        if (p.payload) setConvId(p.payload.conversation_id);
        state.done = true;
        return;
      }
      if (p.type !== "conversation-turn-stream" || !p.payload) return;
      const inner = p.payload;
      setConvId(inner.conversation_id);
      // messageId = the stream-item turn_id (present on stream-item AND done).
      if (inner.turn_id && !state.messageId) state.messageId = inner.turn_id;
      if (inner.type === "done") {
        state.done = true;
        return;
      }
      if (inner.type === "stream-item") {
        feedEncodedItem(inner.encoded_item);
      }
    }

    return {
      state,
      // feed one WS TEXT frame (a JSON array of message/reply objects).
      feed(frameString) {
        let arr;
        try {
          arr = JSON.parse(frameString);
        } catch {
          return;
        }
        const list = Array.isArray(arr) ? arr : [arr];
        for (const el of list) {
          if (!el || typeof el !== "object") continue;
          if (el.type === "message") {
            processMessageObj(el);
          } else if (
            el.type === "reply" &&
            el.reply &&
            Array.isArray(el.reply.catchups)
          ) {
            // Subscribe-recovery catchups are message objects — walk identically.
            for (const m of el.reply.catchups) processMessageObj(m);
          }
        }
      },
      finalize() {
        // A very short answer can arrive as a snapshot only (no append ops) —
        // fall back to the assistant snapshot parts.
        if (!appendedAny && snapshotText.length > state.text.length) {
          state.text = snapshotText;
        }
      },
    };
  }

  // chatGPTWSFrameIsTurnStart reports whether a WS text frame is a `subscribe`
  // reply on a `conversation-turn-*` topic — the turn boundary the transport
  // uses to reset a fresh per-turn accumulator on the multiplexed global socket.
  // Pure + fail-soft (non-string / malformed / non-subscribe → false).
  function chatGPTWSFrameIsTurnStart(frameString) {
    let arr;
    try {
      arr = JSON.parse(frameString);
    } catch {
      return false;
    }
    const list = Array.isArray(arr) ? arr : [arr];
    for (const el of list) {
      if (
        el &&
        el.type === "reply" &&
        el.reply &&
        el.reply.type === "subscribe" &&
        typeof el.reply.topic_id === "string" &&
        el.reply.topic_id.indexOf("conversation-turn-") === 0
      ) {
        return true;
      }
    }
    return false;
  }

  // chatGPTWSFrameRoute inspects one WS text frame and returns how the transport
  // should route it on the MULTIPLEXED global socket (which interleaves
  // sequential/overlapping turns). Pure + fail-soft. Returns:
  //   { turnStart, topicId, completeConvId }
  //   * topicId       — the per-turn key (== turn_id) for a subscribe reply OR a
  //                     conversation-turn message/done frame. "" if none.
  //   * turnStart     — true when this is a `subscribe` reply on a
  //                     conversation-turn topic (reset that topic's accumulator).
  //   * completeConvId— the conversation_id of a secondary `conversation-turn-
  //                     complete` on the "conversations" topic (carries NO
  //                     turn_id — the transport correlates by conversation_id).
  // topicId is the normalized turn_id: topic_id is "conversation-turn-<turn_id>"
  // and the stream-item carries the same turn_id, so both agree with the
  // accumulator's state.messageId.
  function chatGPTWSFrameRoute(frameString) {
    const out = { turnStart: false, topicId: "", completeConvId: "" };
    let arr;
    try {
      arr = JSON.parse(frameString);
    } catch {
      return out;
    }
    const list = Array.isArray(arr) ? arr : [arr];
    for (const el of list) {
      if (!el || typeof el !== "object") continue;
      if (el.type === "reply" && el.reply) {
        const t = el.reply.topic_id;
        if (
          el.reply.type === "subscribe" &&
          typeof t === "string" &&
          t.indexOf("conversation-turn-") === 0
        ) {
          out.turnStart = true;
          out.topicId = normalizeTurnId(t);
          return out;
        }
        continue; // unsubscribe / other reply → not a turn carrier
      }
      if (el.type === "message") {
        const topic = el.topic_id;
        if (topic === "conversations") {
          const p = el.payload;
          if (
            p &&
            p.type === "conversation-turn-complete" &&
            p.payload &&
            typeof p.payload.conversation_id === "string"
          ) {
            out.completeConvId = p.payload.conversation_id;
          }
          continue;
        }
        // Prefer the authoritative inner turn_id; fall back to the topic id.
        const inner = el.payload && el.payload.payload;
        if (inner && typeof inner.turn_id === "string" && inner.turn_id) {
          out.topicId = inner.turn_id;
          return out;
        }
        if (typeof topic === "string" && topic.indexOf("conversation-turn-") === 0) {
          out.topicId = normalizeTurnId(topic);
          return out;
        }
      }
    }
    return out;
  }

  // chatGPTWSSplitFrame splits ONE WS text frame into PER-ELEMENT routing parts
  // so the transport can route each element to the accumulator for ITS OWN
  // topic. A single WS frame may (in principle) BATCH messages from two
  // different turns; routing the whole array to the first topic's accumulator
  // would append turn B's text onto turn A (2026-07-17 round-2 review). Each
  // returned part is `{ turnStart, topicId, completeConvId, frame }` where
  // `frame` is a single-element WS-frame STRING ready to feed to that topic's
  // accumulator. A `reply` (subscribe + catchups) targets ONE topic and is one
  // part. Elements with no turn topic (unsubscribe, non-turn message) are
  // dropped. Pure + fail-soft.
  function chatGPTWSSplitFrame(frameString) {
    const parts = [];
    let arr;
    try {
      arr = JSON.parse(frameString);
    } catch {
      return parts;
    }
    const list = Array.isArray(arr) ? arr : [arr];

    // messagePart computes the independently-routed part for ONE `message`
    // element — used for BOTH top-level messages AND each catchup inside a
    // subscribe reply, so a catchup is keyed by ITS OWN topic, never the reply's.
    // Returns null when the element carries no turn (non-turn topic, etc.).
    function messagePart(el) {
      if (!el || el.type !== "message") return null;
      const topic = el.topic_id;
      const part = {
        turnStart: false,
        topicId: "",
        completeConvId: "",
        frame: JSON.stringify([el]),
      };
      if (topic === "conversations") {
        const p = el.payload;
        if (
          p &&
          p.type === "conversation-turn-complete" &&
          p.payload &&
          typeof p.payload.conversation_id === "string"
        ) {
          part.completeConvId = p.payload.conversation_id;
          return part;
        }
        return null;
      }
      const inner = el.payload && el.payload.payload;
      if (inner && typeof inner.turn_id === "string" && inner.turn_id) {
        part.topicId = inner.turn_id;
        return part;
      }
      if (typeof topic === "string" && topic.indexOf("conversation-turn-") === 0) {
        part.topicId = normalizeTurnId(topic);
        return part;
      }
      return null;
    }

    for (const el of list) {
      if (!el || typeof el !== "object") continue;
      if (el.type === "reply" && el.reply) {
        const t = el.reply.topic_id;
        const isSub =
          el.reply.type === "subscribe" &&
          typeof t === "string" &&
          t.indexOf("conversation-turn-") === 0;
        if (isSub) {
          // Turn-start part FIRST (catchup-FREE — empty catchups so no message
          // data rides on it), so the subscribed topic's accumulator resets
          // BEFORE its catchups feed.
          parts.push({
            turnStart: true,
            topicId: normalizeTurnId(t),
            completeConvId: "",
            frame: JSON.stringify([{ ...el, reply: { ...el.reply, catchups: [] } }]),
          });
        }
        // Route EACH catchup independently by ITS OWN topic_id. In practice a
        // subscribe reply's catchups replay the single subscribed topic, but a
        // mixed batch must NOT cross-leak into the reply's topic accumulator
        // (nor leak workingTurnId/handoffId) — protocol-unlikely, enforced.
        const catchups = Array.isArray(el.reply.catchups) ? el.reply.catchups : [];
        for (const cu of catchups) {
          const cp = messagePart(cu);
          if (cp) parts.push(cp);
        }
        continue; // unsubscribe / other reply → no turn-start, no catchups
      }
      const mp = messagePart(el);
      if (mp) parts.push(mp);
    }
    return parts;
  }

  // hasResponseContent reports whether a finalized accumulator state carries
  // real ASSISTANT/response text — as opposed to merely a conversation id or
  // the outbound prompt. It is the strict predicate the mid-stream-error branch
  // uses to decide "genuine partial capture" vs "failed request": emitTurn's
  // own `hasSomething` (conversationId || text || prompt) is deliberately loose
  // (a prompt alone emits an EMIT-ANYWAY turn), which is wrong for a request
  // whose stream broke before any answer arrived. Pure + finalize-independent:
  // the caller must finalize the accumulator first (Gemini harvests at
  // finalize; Claude/ChatGPT build state.text during feed).
  function hasResponseContent(state) {
    return !!(state && typeof state.text === "string" && state.text.length > 0);
  }

  return {
    joinParts,
    hasResponseContent,
    parseChatGPTRequest,
    parseClaudeRequest,
    parsePerplexityRequest,
    parseGeminiRequest,
    makeChatGPTAccumulator,
    makeChatGPTWSAccumulator,
    chatGPTWSFrameIsTurnStart,
    chatGPTWSFrameRoute,
    chatGPTWSSplitFrame,
    makeClaudeAccumulator,
    makePerplexityAccumulator,
    perplexityThreadIdFromPathname,
    makePerplexityThreadResolver,
    makeGeminiAccumulator,
    copilotJoinContent,
    copilotPartText,
    rewriteCopilotContent,
    parseCopilotSendFrame,
    copilotTurnDisposition,
    copilotShouldEmit,
    copilotTaintNext,
    makeCopilotAccumulator,
    capContentField,
    coerceContentText,
    coercePartText,
    MAX_CONTENT_FIELD_BYTES,
    CONTENT_TRUNCATION_MARKER,
    isChatGPTResumePath,
    chatGPTIsHandoffPending,
    mergeChatGPTLegs,
    selectHandoffPending,
    resolveIdSource,
    deriveHealthBeacon,
    // Two-leg correlator helpers (exported for unit tests + reuse).
    normalizeTurnId,
    decodeJWTPayload,
    turnTopicFromJWT,
    handoffIdFromFrame,
  };
});
