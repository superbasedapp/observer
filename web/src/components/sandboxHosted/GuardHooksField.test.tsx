// Component test of the Hosted sandboxes panel's "Guard in the box" picker
// (lane HOOKS, SBXD-6): the default reads as auto, the saved value shows,
// the internal names stay behind Technical details, and an organization pin
// is said.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { GUARD_HOOKS, GuardHooksField, guardHooksValue } from "@/components/sandboxHosted/GuardHooksField";

test("guardHooksValue: unset and unknown values read as the default", () => {
  assert.equal(guardHooksValue(undefined), "auto");
  assert.equal(guardHooksValue(""), "auto");
  assert.equal(guardHooksValue("bogus"), "auto");
  for (const o of GUARD_HOOKS) assert.equal(guardHooksValue(o.value), o.value);
  assert.deepEqual(GUARD_HOOKS.map((o) => o.value), ["auto", "on", "off"]);
});

test("GuardHooksField: plain words, technical names behind the tooltip, the pin said", () => {
  const html = renderToStaticMarkup(<GuardHooksField value={undefined} disabled={false} pinned={false} onChange={() => {}} />);
  assert.match(html, /Guard in the box/);
  assert.match(html, /When guard enforcement is on for this machine \(default\)/);
  assert.match(html, /Nothing\s+is written on this machine/);
  assert.match(html, /Technical details for guard in the box/);
  assert.doesNotMatch(html, /Set by your organization/);
  const on = renderToStaticMarkup(<GuardHooksField value="on" disabled pinned onChange={() => {}} />);
  assert.match(on, /Always/);
  assert.match(on, /Set by your organization \(it can only turn this on\)/);
});
