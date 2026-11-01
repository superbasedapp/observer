// Component tests of the Code security page's Explain button (component
// security.feedback; security pillar plan section 5.11 (b)), rendered with
// react-dom/server under node's test runner (scripts/test-components.mjs).
// The pure decisions are pinned in src/lib/codeSecurityExplain.test.ts;
// these prove the button renders them: hidden unless security.feedback is
// selected, the advisory label under an answer, disabled while asking.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { ExplainButton, ExplainButtonView } from "@/components/security/ExplainButton";
import { explainView } from "@/lib/codeSecurityExplain";

test("the button is hidden while security.feedback is not selected", () => {
  for (const selected of [undefined, null, [], ["security", "security.code"]]) {
    const html = renderToStaticMarkup(<ExplainButton findingId="f1" token="t" selected={selected} />);
    assert.equal(html, "", `selected=${JSON.stringify(selected)}`);
  }
});

test("the button shows, enabled, once security.feedback is selected", () => {
  const html = renderToStaticMarkup(<ExplainButton findingId="f1" token="t" selected={["security", "security.feedback"]} />);
  assert.match(html, /data-testid="code-security-explain-f1"/);
  assert.match(html, />Explain</);
  assert.doesNotMatch(html, /disabled/);
});

test("the button is disabled and says so while the judge is asked", () => {
  const html = renderToStaticMarkup(<ExplainButtonView findingId="f1" busy={true} view={null} onExplain={() => {}} />);
  assert.match(html, /<button[^>]*disabled/);
  assert.match(html, /Asking the judge\.\.\./);
});

test("an answer carries the advisory label and names the model", () => {
  const view = explainView({ available: true, advisory: true, text: "<b>x</b> is risky", model: "m1", hosting: "loopback" });
  const html = renderToStaticMarkup(<ExplainButtonView findingId="f1" busy={false} view={view} onExplain={() => {}} />);
  assert.match(html, /Advisory: it does not change this finding\. \(m1, loopback\)/);
  // The judge's text is plain text, never markup.
  assert.match(html, /&lt;b&gt;x&lt;\/b&gt; is risky/);
});

test("no answer shows the honest reason and no advisory note", () => {
  const view = explainView({ available: false, advisory: true, reason: "no judge is configured" });
  const html = renderToStaticMarkup(<ExplainButtonView findingId="f1" busy={false} view={view} onExplain={() => {}} />);
  assert.match(html, /no judge is configured/);
  assert.doesNotMatch(html, /Advisory/);
});
