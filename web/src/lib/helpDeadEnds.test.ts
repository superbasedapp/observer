import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { HELP_REGISTRY } from "./help.ts";

// T-471 (D-003, D-322): copy must not send the user to a CLI for something
// the dashboard already does. Each row is a claim that went stale when a
// dashboard control shipped, with the control that replaced it.
const STALE_CLAIMS: ReadonlyArray<{ claim: RegExp; control: string }> = [
  // T-421 built Connected tools > Set up > "Remove Observer's wiring".
  { claim: /dashboard\s+cannot\s+remove\s+it\s+yet/i, control: "Connected tools" },
];

// Lane L5 (dashboard CLI parity, 2026-11-06): help text sent people to a
// terminal or to config.toml for things the dashboard does. Each row is a
// phrase that must not come back, with the control the topic now names.
const L5_STALE_CLAIMS: ReadonlyArray<{ claim: RegExp; control: string }> = [
  { claim: /observer serve/, control: "Restart daemon" },
  { claim: /restart\s+`observer start`/i, control: "Restart daemon" },
  { claim: /Restart with `observer start`/, control: "Restart daemon" },
  { claim: /in ~\/\.observer\/config\.toml and restart/, control: "Settings > Cache tracking" },
  { claim: /Run `observer cache-health --json`/, control: "Full report" },
  { claim: /tunable via observer cache-health/, control: "Full report" },
  // The key never existed: shell filters ship with the binary.
  { claim: /compression\.shell\.filters/, control: "Exclude commands" },
  { claim: /\[compression\.conversation\]\.enabled` in observer config/, control: "Settings > Compression" },
  { claim: /stays a hand-written config decision/, control: "consent" },
  { claim: /\[guard\.cloud\][^.]*deliberately NOT editable from the dashboard/, control: "Network features" },
  { claim: /Verify audit chain button on the Coverage tab \(it runs `observer guard verify-audit`\)\. The chain/, control: "Repair audit chain" },
  { claim: /Edit policy via \[routing\] in config/, control: "Settings > Routing" },
  { claim: /or an `observer doctor` run/, control: "Settings > Health" },
];

test("no help entry sends the user to a terminal or config.toml for a dashboard control (lane L5)", () => {
  for (const e of HELP_REGISTRY) {
    const t = [e.oneLiner, e.detail ?? ""].join("\n");
    for (const { claim } of L5_STALE_CLAIMS) assert.ok(!claim.test(t), `${e.id} says ${claim}`);
  }
  const all = HELP_REGISTRY.map((e) => [e.oneLiner, e.detail ?? ""].join("\n")).join("\n");
  for (const { control } of L5_STALE_CLAIMS) assert.ok(all.includes(control), `no help entry names ${control}`);
});

test("no help entry repeats a stale CLI-only claim", () => {
  for (const e of HELP_REGISTRY) {
    const t = [e.oneLiner, e.detail ?? ""].join("\n");
    for (const { claim } of STALE_CLAIMS) assert.ok(!claim.test(t), `${e.id} says ${claim}`);
  }
});

test("the MCP value-meter help points at the dashboard removal control", () => {
  const e = HELP_REGISTRY.find((x) => x.id === "glossary.settings_mcp");
  assert.ok(e?.detail);
  assert.match(e.detail, /Connected tools/);
  assert.match(e.detail, /Remove Observer's wiring/);
});

test("the Settings MCP card does not repeat a stale CLI-only claim", () => {
  const src = readFileSync(new URL("../pages/Settings.tsx", import.meta.url), "utf8").replace(/\s+/g, " ");
  for (const { claim, control } of STALE_CLAIMS) {
    assert.ok(!claim.test(src), `Settings.tsx says ${claim}`);
    assert.ok(src.includes(control), `Settings.tsx does not name ${control}`);
  }
});
