import assert from "node:assert/strict";
import test from "node:test";

import {
  mb,
  opengrepAcceptLabel,
  opengrepInstallLine,
  opengrepRows,
  opengrepScheduleLabel,
  opengrepStage,
  type OpengrepStatus,
} from "./opengrepCard.ts";

function status(over: Partial<OpengrepStatus>): OpengrepStatus {
  return {
    selected: true,
    managed: false,
    version: "1.30.1",
    download_bytes: 46_600_000,
    tree_bytes: 246_000_000,
    tree_files: 102,
    consented: false,
    installed: false,
    installing: false,
    post_write: true,
    commit_diff: true,
    schedule_hours: 0,
    ...over,
  };
}

test("stages", () => {
  assert.equal(opengrepStage(status({})), "waiting");
  assert.equal(opengrepStage(status({ installing: true })), "installing");
  assert.equal(opengrepStage(status({ installed: true })), "installed");
  assert.equal(opengrepStage(status({ blocked: "pin_owed", version: undefined })), "blocked");
  assert.equal(opengrepStage(status({ managed: true })), "managed");
});

test("before the consent the line states both sizes and that nothing runs", () => {
  const line = opengrepInstallLine(status({}));
  assert.ok(line.includes("about 47 MB"), line);
  assert.ok(line.includes("about 246 MB"), line);
  assert.ok(line.includes("no process starts"), line);
  assert.ok(!line.includes("—") && !line.includes("–"), "no em or en dash");
});

test("sizes and labels", () => {
  assert.equal(mb(0), "an unknown amount");
  assert.equal(mb(500), "less than 1 MB");
  assert.equal(opengrepAcceptLabel(status({})), "Accept and download about 47 MB");
  assert.equal(opengrepAcceptLabel(status({ managed: true })), "Install from the org mirror");
  assert.equal(opengrepScheduleLabel(0), "off");
  assert.equal(opengrepScheduleLabel(24), "daily");
  assert.equal(opengrepScheduleLabel(168), "weekly");
});

test("rows name engine, verification, pack, last run, schedule and isolation; a failed fetch is never current", () => {
  const rows = opengrepRows(
    status({
      engine: "/c/bin/opengrep",
      verification: "verified (manifest_pin)",
      pack_version: "1.1.0",
      pack_source: "imported",
      pack_freshness: "stale",
      fetch_source: "vendor_feed",
      fetch_at: "2026-10-22T08:00:00Z",
      fetch_error: "connection refused",
      schedule_hours: 168,
      isolation: "isolated: bwrap one-shot with no network",
    }),
  );
  const m = new Map(rows);
  assert.deepEqual([...m.keys()], ["Engine", "Verification", "Rule pack", "Last content fetch", "Last run", "Intrafile taint pass", "Triggers", "Isolation"]);
  assert.ok(m.get("Rule pack")?.includes("signed update, stale"));
  assert.ok(m.get("Last content fetch")?.includes("never current"));
  assert.ok(m.get("Triggers")?.includes("full scan weekly"));
  assert.equal(m.get("Last run"), "none");
});

test("the intrafile taint pass row names the last full scan's pass status", () => {
  const m = new Map(
    opengrepRows(
      status({
        last_taint_pass: "timed_out (budget_exhausted): 6 of 8 batches merged",
        last_taint_pass_at: "2026-11-05T08:00:00Z",
      }),
    ),
  );
  assert.ok(m.get("Intrafile taint pass")?.startsWith("timed_out (budget_exhausted): 6 of 8 batches merged (full scan at "));
  assert.equal(new Map(opengrepRows(status({}))).get("Intrafile taint pass"), "none");
});
