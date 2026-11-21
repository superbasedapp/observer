// Component tests of the link from a sentence in an assessment dialog to the
// exact setting it names (polish round, N-10), rendered with react-dom/server
// under node's test runner (scripts/test-components.mjs, no DOM). A click and
// the scroll the Settings card does on arrival are in the Playwright spec; these
// prove what the link says, where it points and that it goes through the gate
// every link to Settings > Guard goes through.

import { before, test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { AssessSettingLink, assessSettingHref, assessSettingLabel } from "@/components/secassess/AssessSettingLink";
import { AssessRequestHelper } from "@/components/secassess/AssessRequestHelper";
import { buildUrl } from "@/lib/api";
import { apiCache } from "@/lib/useApi";
import { ASSESS_HELPER_SETTING } from "@/lib/secAssess";

const GOVERNANCE_PATH = buildUrl("/api/governance");
const lists = { hidden_sections: [], read_only_sections: [], hidden_settings: [], read_only_settings: [] };
const SOLO = { active: false, state: "no_grant", version: 0, notice: {}, ...lists };
const MANAGED = { ...SOLO, managed: true, visibility: { managed_defaults: true, ...lists, hidden_settings: ["guard"] } };
const answer = (g: unknown) => apiCache.fetch(GOVERNANCE_PATH, async () => g);

function render(el: React.ReactElement): string {
  return renderToStaticMarkup(<MemoryRouter>{el}</MemoryRouter>);
}

before(() => answer(SOLO));

test("the link goes to the exact row of the Code security card, in the words of its label", async () => {
  await answer(SOLO);
  const html = render(<AssessSettingLink settingKey={ASSESS_HELPER_SETTING} />);
  assert.match(html, /<a [^>]*href="\/settings\?section=guard#security\.assessments\.probe_helper"/);
  assert.match(html, /data-testid="assess-setting-link"/);
  assert.match(html, />Open the setting &quot;Request helper for penetration tests&quot;</);
  assert.equal(assessSettingHref("security.assessments.probe_helper"), "/settings?section=guard#security.assessments.probe_helper");
  assert.equal(assessSettingLabel(ASSESS_HELPER_SETTING), "Request helper for penetration tests");
});

test("a key the settings table does not hold has no link, never a dead one", () => {
  assert.equal(assessSettingLabel("security.assessments.no_such_row"), "");
  assert.equal(render(<AssessSettingLink settingKey="security.assessments.no_such_row" />), "");
});

test("on a managed machine that hides the Guard section the link reads Managed by your organization and goes nowhere", async () => {
  await answer(MANAGED);
  try {
    const html = render(<AssessSettingLink settingKey={ASSESS_HELPER_SETTING} />);
    assert.doesNotMatch(html, /<a /);
    assert.match(html, /Managed by your organization/);
  } finally {
    await answer(SOLO);
  }
});

test("the plan's request helper block links to the switch only when the helper is off", async () => {
  await answer(SOLO);
  const probe = { dir: ".observer/assessments/x", budget: 600, pace_rps: 5 };
  const off = render(<AssessRequestHelper probe={{ ...probe, state: "off" }} />);
  assert.match(off, /href="\/settings\?section=guard#security\.assessments\.probe_helper"/);
  // Left out for want of python3 is not a setting, and a helper that is on has nothing to switch.
  const withheld = render(<AssessRequestHelper probe={{ ...probe, state: "withheld", withheld_reason: "python3 was not seen." }} />);
  assert.doesNotMatch(withheld, /assess-setting-link/);
  const on = render(<AssessRequestHelper probe={{ ...probe, state: "on", files: ["probe.py", "probe.json"] }} />);
  assert.doesNotMatch(on, /assess-setting-link/);
});
