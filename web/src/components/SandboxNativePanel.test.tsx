// Render tests of the agent's own sandbox panel (lane SBX-P3D), rendered
// with react-dom/server under node's test runner
// (scripts/test-components.mjs).

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { SandboxNativePanel, normalizeVendorForced, VENDOR_FORCED_OPTIONS } from "@/components/SandboxNativePanel";

test("the default is nest_or_refuse and both values are offered", () => {
  assert.equal(normalizeVendorForced(undefined), "nest_or_refuse");
  assert.equal(normalizeVendorForced("refuse"), "refuse");
  assert.equal(normalizeVendorForced("run_without"), "nest_or_refuse");
  assert.deepEqual(
    VENDOR_FORCED_OPTIONS.map((o) => o.value),
    ["nest_or_refuse", "refuse"],
  );
  const html = renderToStaticMarkup(<SandboxNativePanel value={undefined} pinned={new Set()} writable onChange={() => {}} />);
  assert.match(html, /checked="" value="nest_or_refuse"/);
  assert.match(html, /the run records that Observer turned the agent&#x27;s own sandbox off/);
  assert.doesNotMatch(html, /Set by your organization/);
});

test("an org pin disables the choice and says so", () => {
  const html = renderToStaticMarkup(
    <SandboxNativePanel value="refuse" pinned={new Set(["vendor_forced_native"])} writable onChange={() => {}} />,
  );
  assert.match(html, /checked="" value="refuse"/);
  assert.match(html, /<fieldset[^>]*disabled=""/);
  assert.match(html, /Set by your organization/);
});

test("a read-only card disables the choice", () => {
  const html = renderToStaticMarkup(<SandboxNativePanel value="nest_or_refuse" pinned={new Set()} writable={false} onChange={() => {}} />);
  assert.match(html, /<fieldset[^>]*disabled=""/);
});
