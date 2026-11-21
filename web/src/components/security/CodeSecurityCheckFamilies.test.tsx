// Component tests of the Coverage tab's "What is checked" (security coverage
// gaps plan section 2): every family is listed with its state in words,
// including the ones not selected, and the card is absent without rows.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { CheckFamiliesCard, familyStateWords } from "@/pages/codesecurity/CheckFamiliesCard";

const families = [
  { family: "dependency_vulnerabilities", label: "Dependency vulnerabilities", components: ["security.scan.scalibr", "security.scan.osv"], state: "on" },
  { family: "code_rules", label: "Code rules", components: ["security.scan.opengrep"], state: "not_selected" },
  { family: "iac", label: "Infrastructure as code", components: ["security.scan.trivy", "security.scan.kics"], state: "not_in_build" },
  { family: "package_provenance", label: "Package provenance", components: ["security.deps"], state: "off", note: `[security.deps] provenance = "off"` },
];

test("every family is listed with its state and components", () => {
  const html = renderToStaticMarkup(<CheckFamiliesCard families={families} />);
  assert.match(html, /data-testid="check-families"/);
  assert.match(html, /1 of 4 checking families on/);
  assert.match(html, /data-family="code_rules"/);
  assert.match(html, />not selected</);
  assert.match(html, />not in this build</);
  assert.match(html, /security\.scan\.trivy, security\.scan\.kics/);
  assert.match(html, /provenance = &quot;off&quot;/);
});

test("no rows (an older daemon): no card", () => {
  assert.equal(renderToStaticMarkup(<CheckFamiliesCard families={undefined} />), "");
  assert.equal(renderToStaticMarkup(<CheckFamiliesCard families={[]} />), "");
});

test("familyStateWords: one row per state, an unknown state reads as its id", () => {
  assert.deepEqual(familyStateWords("on"), { words: "on", tone: "success" });
  assert.deepEqual(familyStateWords("off"), { words: "off", tone: "warn" });
  assert.equal(familyStateWords("not_selected").words, "not selected");
  assert.equal(familyStateWords("not_in_build").words, "not in this build");
  assert.deepEqual(familyStateWords("brand_new"), { words: "brand new", tone: "neutral" });
});
