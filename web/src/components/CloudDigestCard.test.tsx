// Render test of the weekly digest's locked card (CloudDigestCard state b):
// the upsell names the paid individual plan "Personal Pro", the only name a
// customer sees for it (operator ruling 2026-11-24), never "Plus" (the
// September beta's name), and carries no price that a price change would
// leave stale in a released binary (it was "USD 15/month, 7-day trial";
// Personal Pro is USD 9 a month with no trial).

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { CloudDigestLockedCard } from "./CloudDigestCard";

test("the locked digest card offers Personal Pro by that name, with no price", () => {
  const html = renderToStaticMarkup(<CloudDigestLockedCard />);
  assert.match(html, /Part of Personal Pro/);
  assert.doesNotMatch(html, /\bPlus\b/);
  assert.doesNotMatch(html, /USD|\$\d|trial/);
  assert.match(html, /href="https:\/\/cloud\.superbased\.app\/portal\/billing"/);
});
