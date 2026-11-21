// W5-6: the React wrapper renders the element and wires its events.
import { test } from "node:test";
import assert from "node:assert/strict";

import { installDom, fakeFetch, TRACE, SPAN, tick } from "./dom.mjs";

installDom();
const React = await import("react");
const { createRoot } = await import("react-dom/client");
const { act } = React;
const { SuperbasedFeedback, feedbackAttributes } = await import("../dist/react.js");

test("feedbackAttributes maps props to the element's attributes", () => {
  assert.deepEqual(feedbackAttributes({ traceId: TRACE, spanId: SPAN, endpoint: "/f", comment: "optional", labelUp: "Yes", crossOrigin: true, disabled: false }), {
    "trace-id": TRACE,
    "span-id": SPAN,
    endpoint: "/f",
    comment: "optional",
    "label-up": "Yes",
    "cross-origin": "",
  });
});

test("SuperbasedFeedback registers the element, passes fetch and calls onFeedback / onSent", async () => {
  const host = document.createElement("div");
  document.body.appendChild(host);
  const root = createRoot(host);
  const f = fakeFetch();
  const seen = [];
  await act(async () => {
    root.render(
      React.createElement(SuperbasedFeedback, {
        traceId: TRACE,
        spanId: SPAN,
        endpoint: "/api/feedback",
        fetch: f,
        className: "fb",
        onFeedback: (p) => seen.push(["feedback", p]),
        onSent: (d) => seen.push(["sent", d.status]),
      }),
    );
  });
  const el = host.querySelector("superbased-feedback");
  assert.ok(el, "rendered");
  assert.ok(customElements.get("superbased-feedback"), "registered on mount");
  assert.equal(el.getAttribute("trace-id"), TRACE);
  assert.equal(el.getAttribute("class"), "fb");
  await act(async () => {
    el.shadowRoot.querySelector("button.up").click();
    await tick();
  });
  assert.deepEqual(seen, [
    ["feedback", { trace_id: TRACE, span_id: SPAN, value: true, name: "user_feedback" }],
    ["sent", 200],
  ]);
  assert.equal(f.calls.length, 1);
  await act(async () => root.unmount());
});

test("onFeedback can take over: preventDefault() and no endpoint means no POST", async () => {
  const host = document.createElement("div");
  document.body.appendChild(host);
  const root = createRoot(host);
  const f = fakeFetch();
  let got = null;
  await act(async () => {
    root.render(React.createElement(SuperbasedFeedback, { traceId: TRACE, endpoint: "/api/feedback", fetch: f, onFeedback: (p, e) => { got = p; e.preventDefault(); } }));
  });
  await act(async () => {
    host.querySelector("superbased-feedback").shadowRoot.querySelector("button.down").click();
    await tick();
  });
  assert.equal(got.value, false);
  assert.equal(f.calls.length, 0);
  await act(async () => root.unmount());
});
