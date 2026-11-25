// Component test of Settings > AI Apps "Use an SDK key from my admin" (lane
// sdk-use-key), rendered with react-dom/server under node's test runner
// (scripts/test-components.mjs). The form's checks are pinned in
// src/lib/sdkDestination.test.ts; this pins the field itself: a password
// field the browser does not autofill or remember, and the gateway address
// prefilled from the saved setting.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { UseAdminKeyForm } from "@/pages/settings/SdkDestinationCard";

const render = (gateway: string) =>
  renderToStaticMarkup(<UseAdminKeyForm defaultGateway={gateway} disabled={false} onBusy={() => {}} onDone={() => {}} />);

test("the key field is a password field with autocomplete off", () => {
  const html = render("");
  assert.match(html, /<input type="password"[^>]*autoComplete="off"/i);
  assert.match(html, /SDK key/);
  assert.match(html, /Install the key/);
  assert.match(html, /does not revoke it/);
});

test("the gateway address is prefilled from the saved setting", () => {
  assert.match(render("https://acme.superbased.app"), /value="https:\/\/acme\.superbased\.app"/);
});
