// Render tests of the shared callout (shared/primitives/Callout), rendered
// with react-dom/server under node's test runner (scripts/test-components.mjs).
// The operator's report (2026-11-18): in the New Terminal dialog a warning
// callout with a long link as its action squeezed its text to about 50px,
// one word per line. The box now wraps: the icon and text keep a minimum
// width and the action drops below them when it does not fit beside them.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { Callout } from "@shared/primitives";
import { CALLOUT_LAYOUT } from "@shared/primitives/Callout";

function classesOf(html: string): string[][] {
  return [...html.matchAll(/class="([^"]*)"/g)].map((m) => m[1].split(/\s+/));
}

test("the callout box wraps so a long action drops below the text", () => {
  const html = renderToStaticMarkup(
    <Callout tone="warn" title="Remote clone is off" action={<a href="/terminals?tab=settings">Open Terminals &gt; Settings &gt; Sandbox isolation</a>}>
      Turn it on to clone a repository in the box.
    </Callout>,
  );
  const [box, lead] = classesOf(html);
  for (const c of ["flex", "flex-wrap"]) assert.ok(box.includes(c), `box has ${c}`);
  // The icon and text group grows, may shrink, and keeps a sane basis.
  for (const c of ["flex", "min-w-0", "flex-1", "basis-56"]) assert.ok(lead.includes(c), `lead has ${c}`);
  // The action may take the whole width on its own line, and wraps itself.
  const action = classesOf(html).find((cs) => cs.includes("self-center"));
  assert.ok(action, "the action wrapper renders");
  for (const c of ["max-w-full", "min-w-0"]) assert.ok(action.includes(c), `action has ${c}`);
  assert.equal(action.join(" "), CALLOUT_LAYOUT.action);
  assert.match(html, /Open Terminals &gt; Settings &gt; Sandbox isolation/);
  assert.match(html, /role="note"/);
});

test("the icon and text stay together in the lead, the action stays outside it", () => {
  const html = renderToStaticMarkup(
    <Callout tone="info" action={<button type="button">Do it</button>}>
      A sentence.
    </Callout>,
  );
  const leadStart = html.indexOf(`class="${CALLOUT_LAYOUT.lead}"`);
  const textAt = html.indexOf("A sentence.");
  const actionAt = html.indexOf(`class="${CALLOUT_LAYOUT.action}"`);
  assert.ok(leadStart >= 0 && leadStart < textAt && textAt < actionAt, "lead holds the text, the action follows it");
  assert.ok(html.indexOf("<svg") > leadStart && html.indexOf("<svg") < textAt, "the icon is inside the lead");
});

test("a callout with no action renders no action wrapper", () => {
  const html = renderToStaticMarkup(<Callout>Only text.</Callout>);
  assert.doesNotMatch(html, /self-center/);
  assert.ok(html.includes(`class="${CALLOUT_LAYOUT.box} `), "the box keeps its wrapping layout");
});
