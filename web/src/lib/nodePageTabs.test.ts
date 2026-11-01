// Pins the node page-tab tables (src/lib/nodePageTabs.ts): every page's
// ids are unique kebab-case, the first id is the default (written as the
// param's absence by useUrlTab), every id has a short label, and a cold deep
// link to each id resolves to that tab while unknown values fall back.
import { test } from "node:test";
import assert from "node:assert/strict";
import { pickEnum } from "../../../shared/lib/urlParams.ts";
import {
  AGENT_CONFIG_TABS,
  CACHE_TABS,
  ROUTING_TABS,
  REMOTE_TABS,
  COMPRESSION_TABS,
  COST_TABS,
  TERMINALS_TABS,
  TOOLS_TABS,
  terminalsHashTab,
  SECURITY_TABS,
  defaultTab,
  reportToCostSearch,
  type PageTabs,
} from "./nodePageTabs.ts";

const PAGES: Record<string, PageTabs<string>> = {
  security: SECURITY_TABS,
  cost: COST_TABS,
  tools: TOOLS_TABS,
  compression: COMPRESSION_TABS,
  cache: CACHE_TABS,
  routing: ROUTING_TABS,
  remote: REMOTE_TABS,
  terminals: TERMINALS_TABS,
  "agent-config": AGENT_CONFIG_TABS,
};

for (const [page, tabs] of Object.entries(PAGES)) {
  test(`${page}: ids are unique kebab-case with a label of at most ~20 chars`, () => {
    assert.equal(new Set(tabs.ids).size, tabs.ids.length);
    assert.ok(tabs.ids.length >= 2 && tabs.ids.length <= 7, "2-7 tabs (plan §1.1)");
    for (const id of tabs.ids) {
      assert.match(id, /^[a-z]+(-[a-z]+)*$/, id);
      const label = tabs.labels[id];
      assert.ok(label && label.length <= 20, `${id}: ${label}`);
      assert.doesNotMatch(label, /—/, "no em dashes");
    }
  });

  test(`${page}: every ?tab= value is a cold deep link; unknown falls back`, () => {
    const def = defaultTab(tabs);
    assert.equal(def, tabs.ids[0]);
    for (const id of tabs.ids) {
      const search = id === def ? "" : `?tab=${id}`;
      assert.equal(pickEnum(new URLSearchParams(search).get("tab"), tabs.ids, def), id);
    }
    for (const s of ["?tab=nope", "?tab=", "?tab=OVERVIEW"]) {
      assert.equal(pickEnum(new URLSearchParams(s).get("tab"), tabs.ids, def), def, s);
    }
  });
}

test("security: the seven tabs of mockup M4, in order", () => {
  assert.deepEqual(
    [...SECURITY_TABS.ids],
    ["overview", "verdicts", "rules", "budgets", "prompt-guard", "mcp", "coverage"],
  );
  assert.equal(SECURITY_TABS.labels.coverage, "Coverage & evidence");
});

test("cost: Statement absorbs /report; the old query string maps onto the tab", () => {
  assert.ok(COST_TABS.ids.includes("statement"));
  assert.equal(reportToCostSearch(""), "?tab=statement");
  assert.equal(reportToCostSearch("?month=2026-09"), "?tab=statement&month=2026-09");
  assert.equal(
    reportToCostSearch("?month=2026-09&project=%2Fhome%2Fu%2Frepo"),
    "?tab=statement&month=2026-09&project=%2Fhome%2Fu%2Frepo",
  );
  assert.equal(reportToCostSearch("?tab=x&month=2026-08"), "?tab=statement&month=2026-08");
});

test("terminals: Workspace is the default and #launch-policy opens Settings", () => {
  assert.equal(defaultTab(TERMINALS_TABS), "workspace");
  assert.equal(terminalsHashTab("#launch-policy"), "settings");
  // T-488 / T-489: the dialog's folder and remote-system links land there too.
  assert.equal(terminalsHashTab("#folder-selection"), "settings");
  assert.equal(terminalsHashTab("#remote-systems"), "settings");
  for (const h of ["", "#", "#other", "#launch-policy-x"]) assert.equal(terminalsHashTab(h), null, h);
});
