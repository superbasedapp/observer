// Where the New Terminal dialog's hosted tool notice links (lane UI, SBXD
// smaller item "the tool notice's link"): Hosted sandboxes, where each
// provider's template is typed, never Sandbox isolation's backends list.

import { test } from "node:test";
import assert from "node:assert/strict";
import { HOSTED_TOOL_PLACE, hostedToolPlace, noticePlace } from "./newTerminalSandbox.ts";
import { PLACES } from "./settingsPlaces.ts";
import { TERMINALS_HOSTED_SANDBOXES_HASH, TERMINALS_SETTINGS_ANCHORS, terminalsHashTab } from "./nodePageTabs.ts";

test("the hosted tool notice links to Hosted sandboxes", () => {
  const cases: [{ place?: string } | null, string][] = [
    [{ place: "terminal_sandbox_hosted" }, "terminal_sandbox_hosted"],
    [{}, "terminal_sandbox_hosted"],
    [null, "terminal_sandbox_hosted"],
    [{ place: "not_a_place" }, "terminal_sandbox_hosted"],
    [{ place: "toString" }, "terminal_sandbox_hosted"],
    [{ place: "terminal_sandbox" }, "terminal_sandbox"],
  ];
  for (const [n, want] of cases) assert.equal(hostedToolPlace(n), want, JSON.stringify(n));
  assert.equal(HOSTED_TOOL_PLACE, "terminal_sandbox_hosted");
  assert.equal(noticePlace({ place: "nope" }, "components"), "components");
});

test("the Hosted sandboxes place opens the Terminals Settings tab at its card", () => {
  const r = PLACES.terminal_sandbox_hosted;
  assert.equal(r.label, "Terminals > Settings > Hosted sandboxes");
  assert.ok(r.href.endsWith(TERMINALS_HOSTED_SANDBOXES_HASH));
  assert.ok(TERMINALS_SETTINGS_ANCHORS.includes(TERMINALS_HOSTED_SANDBOXES_HASH));
  assert.equal(terminalsHashTab(TERMINALS_HOSTED_SANDBOXES_HASH), "settings");
});
