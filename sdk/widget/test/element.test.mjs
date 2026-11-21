// W5-6: the <superbased-feedback> web component, in happy-dom.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";

import { installDom, fakeFetch, TRACE, SPAN, tick } from "./dom.mjs";

installDom();
const w = await import("../dist/index.js");
w.defineFeedbackElement();

beforeEach(() => {
  document.body.innerHTML = "";
});

function mount(attrs = {}) {
  const el = document.createElement("superbased-feedback");
  for (const [k, v] of Object.entries({ "trace-id": TRACE, ...attrs })) el.setAttribute(k, v);
  document.body.appendChild(el);
  return el;
}
const q = (el, sel) => el.shadowRoot.querySelector(sel);
const events = (el) => {
  const got = [];
  for (const n of [w.FEEDBACK_EVENT, w.SENT_EVENT, w.ERROR_EVENT]) el.addEventListener(n, (e) => got.push([n, e.detail]));
  return got;
};

test("loads without a DOM-less crash, defines once, and renders accessible controls", () => {
  assert.equal(w.defineFeedbackElement(), "superbased-feedback");
  assert.equal(w.defineFeedbackElement(), "superbased-feedback", "idempotent");
  const el = mount();
  const group = q(el, "[role=group]");
  assert.equal(q(el, `#${group.getAttribute("aria-labelledby")}`).textContent, "Was this answer helpful?");
  const up = q(el, "button.up");
  const down = q(el, "button.down");
  assert.equal(up.getAttribute("type"), "button");
  assert.equal(up.getAttribute("aria-label"), "Helpful");
  assert.equal(down.getAttribute("aria-label"), "Not helpful");
  assert.equal(up.getAttribute("aria-pressed"), "false");
  assert.equal(q(el, "[role=status]").getAttribute("aria-live"), "polite");
  assert.equal(q(el, "form.comment").hidden, true);
  assert.equal(el.value, null);
});

test("a thumbs up posts the SDK's feedback fields to the app's own endpoint, and says thanks", async () => {
  const el = mount({ "span-id": SPAN.toUpperCase(), endpoint: "/api/feedback", token: "sig-abc" });
  const f = fakeFetch(204);
  el.fetch = f;
  const got = events(el);
  q(el, "button.up").click();
  await tick();
  assert.equal(f.calls.length, 1);
  const c = f.calls[0];
  assert.equal(c.url, "/api/feedback");
  assert.equal(c.init.method, "POST");
  assert.equal(c.init.credentials, "same-origin");
  assert.equal(c.init.redirect, "error");
  assert.deepEqual(c.body, { trace_id: TRACE, span_id: SPAN, value: true, name: "user_feedback", token: "sig-abc" });
  for (const h of Object.keys(c.init.headers)) assert.ok(!/authorization|api-key/i.test(h), "the widget never sends a key");
  assert.deepEqual(got.map((g) => g[0]), [w.FEEDBACK_EVENT, w.SENT_EVENT]);
  assert.equal(q(el, "[role=status]").textContent, "Thanks for your feedback.");
  assert.equal(q(el, "button.up").getAttribute("aria-pressed"), "true");
  assert.equal(q(el, "button.up").disabled, true, "one vote per answer");
  assert.equal(el.value, true);
});

test("without an endpoint only the event fires; preventDefault() skips the POST", async () => {
  const el = mount();
  const got = events(el);
  q(el, "button.down").click();
  await tick();
  assert.deepEqual(got, [[w.FEEDBACK_EVENT, { trace_id: TRACE, value: false, name: "user_feedback" }]]);
  const el2 = mount({ endpoint: "/api/feedback" });
  const f = fakeFetch();
  el2.fetch = f;
  el2.addEventListener(w.FEEDBACK_EVENT, (e) => e.preventDefault());
  q(el2, "button.up").click();
  await tick();
  assert.equal(f.calls.length, 0);
});

test("comment=optional: the comment box opens on a vote, keyboard submit and Escape skip", async () => {
  const el = mount({ endpoint: "/api/feedback", comment: "optional" });
  const f = fakeFetch();
  el.fetch = f;
  q(el, "button.down").click();
  const form = q(el, "form.comment");
  assert.equal(form.hidden, false);
  const ta = q(el, "textarea");
  assert.equal(el.shadowRoot.activeElement, ta, "focus moves to the comment");
  assert.equal(q(el, `label[for="${ta.id}"]`).textContent, "Tell us more (optional)");
  ta.value = "  wrong city  ";
  ta.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", ctrlKey: true, bubbles: true }));
  await tick();
  assert.deepEqual(f.calls[0].body, { trace_id: TRACE, value: false, name: "user_feedback", comment: "wrong city" });
  const el2 = mount({ endpoint: "/api/feedback", comment: "optional" });
  const f2 = fakeFetch();
  el2.fetch = f2;
  q(el2, "button.up").click();
  q(el2, "textarea").value = "ignored";
  q(el2, "textarea").dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
  await tick();
  assert.equal(f2.calls[0].body.comment, undefined, "Escape skips the comment, the vote still goes");
});

test("comment=required: a thumbs-down needs a comment; the hint is announced and Skip is hidden", async () => {
  const el = mount({ endpoint: "/api/feedback", comment: "required", "comment-required-text": "Say why" });
  const f = fakeFetch();
  el.fetch = f;
  q(el, "button.down").click();
  assert.equal(q(el, "button.skip").hidden, true);
  assert.equal(q(el, "textarea").getAttribute("aria-required"), "true");
  q(el, "button.send").click();
  await tick();
  assert.equal(f.calls.length, 0);
  assert.equal(q(el, ".hint").textContent, "Say why");
  assert.equal(q(el, ".hint").getAttribute("aria-live"), "assertive");
  assert.equal(q(el, "textarea").getAttribute("aria-invalid"), "true");
  q(el, "textarea").value = "too vague";
  q(el, "button.send").click();
  await tick();
  assert.equal(f.calls[0].body.comment, "too vague");
});

test("a failed POST or a bad trace id is an error event and an error status; the user can vote again", async () => {
  const el = mount({ endpoint: "/api/feedback" });
  el.fetch = fakeFetch(500);
  const got = events(el);
  q(el, "button.up").click();
  await tick();
  assert.equal(got.at(-1)[0], w.ERROR_EVENT);
  assert.equal(got.at(-1)[1].status, 500);
  assert.equal(q(el, "[role=status]").textContent, "Your feedback could not be sent.");
  el.fetch = fakeFetch(200);
  el.retry();
  await tick();
  assert.equal(got.at(-1)[0], w.SENT_EVENT);
  const bad = mount({ "trace-id": "nope", endpoint: "/api/feedback" });
  const gotBad = events(bad);
  bad.fetch = fakeFetch();
  q(bad, "button.up").click();
  await tick();
  assert.deepEqual(gotBad.map((g) => g[0]), [w.ERROR_EVENT]);
  assert.match(gotBad[0][1].error, /trace-id/);
  assert.equal(bad.fetch.calls.length, 0);
  const net = mount({ endpoint: "/api/feedback" });
  net.fetch = fakeFetch("throw");
  const gotNet = events(net);
  q(net, "button.down").click();
  await tick();
  assert.equal(gotNet.at(-1)[1].error, "network down");
});

test("the endpoint stays on the page's origin unless cross-origin is set; never a non-http scheme", async () => {
  assert.equal(w.endpointAllowed("/api/feedback", "https://app.example"), true);
  assert.equal(w.endpointAllowed("https://app.example/x", "https://app.example"), true);
  assert.equal(w.endpointAllowed("https://collector.other/x", "https://app.example"), false);
  assert.equal(w.endpointAllowed("https://collector.other/x", "https://app.example", true), true);
  assert.equal(w.endpointAllowed("javascript:alert(1)", "https://app.example", true), false);
  const el = mount({ endpoint: "https://evil.example/collect" });
  el.fetch = fakeFetch();
  const got = events(el);
  q(el, "button.up").click();
  await tick();
  assert.equal(el.fetch.calls.length, 0);
  assert.match(got.at(-1)[1].error, /not on this page's origin/);
});

test("texts are attributes, a new trace id resets the vote, disabled blocks voting, and the theme is CSS variables", async () => {
  const el = mount({ question: "Did this help?", "label-up": "Yes", "label-down": "No" });
  assert.equal(q(el, ".question").textContent, "Did this help?");
  assert.equal(q(el, "button.up").getAttribute("aria-label"), "Yes");
  q(el, "button.up").click();
  await tick();
  assert.equal(el.value, true);
  el.setAttribute("trace-id", "0af7651916cd43dd8448eb211c80319c");
  assert.equal(el.value, null);
  assert.equal(q(el, "button.up").disabled, false);
  el.setAttribute("disabled", "");
  assert.equal(q(el, "button.up").disabled, true);
  const css = el.shadowRoot.adoptedStyleSheets.map((sh) => [...sh.cssRules].map((r) => r.cssText).join("\n")).join("\n");
  for (const v of w.CSS_VARIABLES) assert.ok(css.includes(`var(${v}`), v);
  assert.ok(q(el, "button.up").getAttribute("part").includes("button"), "::part() hooks for deeper styling");
});

test("validatePayload mirrors the SDKs' feedback() rules", () => {
  const ok = { trace_id: TRACE, value: true, name: "user_feedback" };
  assert.equal(w.validatePayload(ok), "");
  assert.match(w.validatePayload({ ...ok, trace_id: "0".repeat(32) }), /trace-id/);
  assert.match(w.validatePayload({ ...ok, span_id: "x" }), /span-id/);
  assert.match(w.validatePayload({ ...ok, name: "Bad Name" }), /name/);
  assert.match(w.validatePayload({ ...ok, comment: "é".repeat(1001) }), /2000 bytes/);
});

test("R-C37: styles need no inline CSS (a strict style-src CSP); the fallback carries the nonce", () => {
  const el = mount();
  assert.equal(q(el, "style"), null, "no inline <style> where constructable stylesheets exist");
  assert.equal(el.shadowRoot.adoptedStyleSheets.length, 1);
  const two = mount();
  assert.equal(two.shadowRoot.adoptedStyleSheets[0], el.shadowRoot.adoptedStyleSheets[0], "one sheet shared per document");
  // An older browser: no constructable stylesheets.
  const host = document.createElement("div");
  const root = host.attachShadow({ mode: "open" });
  Object.defineProperty(root, "adoptedStyleSheets", { value: undefined, configurable: true });
  delete root.adoptedStyleSheets;
  const real = window.CSSStyleSheet;
  window.CSSStyleSheet = undefined;
  try {
    assert.equal(w.applyStyles(root, "n0nce"), "style");
    assert.equal(root.querySelector("style").getAttribute("nonce"), "n0nce");
  } finally {
    window.CSSStyleSheet = real;
  }
});

test("R-C37: a comment over 2,000 bytes but under 2,000 characters is held back with a hint; the vote is kept", async () => {
  const f = fakeFetch();
  const el = mount({ comment: "optional", endpoint: "/api/feedback" });
  el.fetch = f;
  q(el, "button.down").click();
  await tick();
  const ta = q(el, "textarea");
  ta.value = "é".repeat(1001); // 1,001 characters, 2,002 bytes: maxlength lets it through
  ta.dispatchEvent(new Event("input"));
  assert.equal(ta.getAttribute("aria-invalid"), "true");
  assert.equal(q(el, ".hint").textContent, "Your comment is too long.");
  q(el, "button.send").click();
  await tick();
  assert.equal(f.calls.length, 0, "nothing is sent");
  assert.equal(q(el, "form.comment").hidden, false, "still editing");
  assert.equal(el.value, false);
  ta.value = "é".repeat(1000); // exactly 2,000 bytes
  ta.dispatchEvent(new Event("input"));
  assert.equal(ta.getAttribute("aria-invalid"), null);
  q(el, "button.send").click();
  await tick();
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].body.comment.length, 1000);
});
