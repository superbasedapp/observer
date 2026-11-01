import assert from "node:assert/strict";
import test from "node:test";

import {
  CODE_SECURITY_SETTINGS,
  codeSecurityCardVisible,
  codeSecurityFieldPaths,
  codeSecurityOptionLabel,
  codeSecurityParse,
  codeSecurityPatch,
  codeSecurityRows,
  codeSecurityValue,
} from "./codeSecuritySettings.ts";
import type { ComponentsView } from "./componentState.ts";

const retention = CODE_SECURITY_SETTINGS[0];

function view(state: string | null): ComponentsView {
  const components = state === null ? [] : [{ id: "security", state }];
  return { components } as unknown as ComponentsView;
}

test("the card shows only while the security component is active", () => {
  assert.equal(codeSecurityCardVisible(view("active")), true);
  for (const s of ["inactive", "absent", "unknown"]) {
    assert.equal(codeSecurityCardVisible(view(s)), false, s);
  }
  assert.equal(codeSecurityCardVisible(view(null)), false, "no row");
  assert.equal(codeSecurityCardVisible(null), false, "unknown state fails closed");
  assert.equal(codeSecurityCardVisible(undefined), false);
});

test("codeSecurityValue reads only a value the picker offers", () => {
  const rows: [unknown, number | null][] = [
    [{ Security: { Retention: { Days: 365 } } }, 365],
    [{ Security: { Retention: { Days: 90 } } }, 90],
    [{ Security: { Retention: { Days: 7 } } }, null],
    [{ Security: { Retention: { Days: "365" } } }, null],
    [{ Security: {} }, null],
    [{}, null],
    [null, null],
  ];
  for (const [cfg, want] of rows) {
    assert.equal(codeSecurityValue(cfg, retention), want, JSON.stringify(cfg));
  }
});

test("codeSecurityPatch moves one key and refuses a value off the picker", () => {
  assert.deepEqual(codeSecurityPatch(retention, 365, 730), { key: "security.retention.days", value: 730, was: 365 });
  assert.equal(codeSecurityPatch(retention, 365, 365), null);
  assert.equal(codeSecurityPatch(retention, 365, 7), null);
  assert.equal(codeSecurityPatch(retention, null, 730), null);
});

test("every row is complete and keyed under security.", () => {
  for (const r of CODE_SECURITY_SETTINGS) {
    assert.ok(r.key.startsWith("security."), r.key);
    assert.ok(r.values.includes(r.defaultValue), r.key);
    assert.ok(r.label && r.help, r.key);
    // A number carries a unit; an on/off row does not.
    assert.equal(typeof r.defaultValue === "number", r.unit !== "", r.key);
    assert.ok(r.component === "security" || r.component.startsWith("security."), r.key);
  }
  assert.deepEqual(codeSecurityFieldPaths(), [
    "Security.Retention.Days",
    "Security.Deps.InstallWaitMS",
    "Security.Deps.MinPackageAgeH",
    "Security.Deps.IndexDownload",
    "Security.Secrets.WriteCheck",
    "Security.Secrets.CommitCheck",
    "Security.Secrets.PostWriteCapKiB",
    "Security.Deps.UnknownAction",
    "Security.Deps.OnlineUnknownAction",
    "Security.Scanning.QuickScanBudgetS",
    "Security.Scanning.MaxScanStalenessMin",
    "Security.Scanning.MinBlockingSeverity",
    "Security.Scanning.HistoryScanOnEnrol",
    "Security.Scanning.ReflogHoldMaxAgeDays",
    "Security.Scanning.ReflogHoldMaxEntries",
    "Security.Trust.Prelaunch",
    "Security.MCP.Tools",
    "Security.Statusline.Segment",
    "Security.Notify.Critical",
    "Security.Custom.ScheduleHours",
    "Security.Custom.PauseOnBattery",
    "Security.Scan.Opengrep.PostWrite",
    "Security.Scan.Opengrep.CommitDiff",
    "Security.Scan.Opengrep.ScheduleHours",
    "Security.Scan.Opengrep.PauseOnBattery",
    "Security.Scan.Opengrep.Feed",
    "Security.Feedback.AfterWrite",
  ]);
});

test("a row shows only while its owning component is active", () => {
  const v = (ids: [string, string][]) => ({ components: ids.map(([id, state]) => ({ id, state })) }) as unknown as ComponentsView;
  const keys = (rows: readonly { key: string }[]) => rows.map((r) => r.key);
  const all = ["security", "security.deps", "security.secrets"];
  const scanning = [
    "security.scanning.quick_scan_budget_s",
    "security.scanning.max_scan_staleness_min",
    "security.scanning.min_blocking_severity",
    "security.scanning.history_scan_on_enrol",
    "security.scanning.reflog_hold_max_age_days",
    "security.scanning.reflog_hold_max_entries",
  ];
  const root = ["security.retention.days", ...scanning, "security.mcp.tools", "security.statusline.segment", "security.notify.critical"];
  assert.deepEqual(keys(codeSecurityRows(v([["security", "active"]]), all)), root);
  assert.deepEqual(keys(codeSecurityRows(v([["security", "active"], ["security.deps", "active"]]), all)), [
    "security.retention.days",
    "security.deps.install_wait_ms",
    "security.deps.min_package_age_h",
    "security.deps.index_download",
    "security.deps.unknown_action",
    "security.deps.online_unknown_action",
    ...scanning,
    "security.mcp.tools",
    "security.statusline.segment",
    "security.notify.critical",
  ]);
  assert.deepEqual(keys(codeSecurityRows(v([["security", "active"], ["security.secrets", "active"]]), all)), [
    "security.retention.days",
    "security.secrets.write_check",
    "security.secrets.commit_check",
    "security.secrets.postwrite_cap_kib",
    ...scanning,
    "security.mcp.tools",
    "security.statusline.segment",
    "security.notify.critical",
  ]);
  assert.deepEqual(keys(codeSecurityRows(v([["security", "active"], ["security.deps", "inactive"]]), all)), root);
  assert.deepEqual(codeSecurityRows(null, all), []);
  assert.deepEqual(codeSecurityRows(v([["security", "active"]]), undefined), [], "unknown selection fails closed");
});

test("an install with no [components] block shows no opt-in child's rows", () => {
  // Every compiled module resolves active with no block (componentstate.Legacy),
  // but the daemon's opt-in rule selects none of the opt-in children, so
  // security_selected lists only the root and the default-on children:
  // since lane sec-deps4 (P-036) that includes security.deps and its two
  // scanner children.
  const optIn = ["security.scan.custom", "security.trust", "security.githooks", "security.feedback", "security.scan.opengrep"];
  const offered = ["security", "security.code", "security.secrets", "security.deps", "security.scan.scalibr", "security.scan.osv"];
  const ids = [...offered, ...optIn];
  const legacy = { components: ids.map((id) => ({ id, state: "active" })) } as unknown as ComponentsView;
  const shown = codeSecurityRows(legacy, offered);
  assert.ok(shown.length > 0, "the root's rows still show");
  for (const r of shown) {
    assert.ok(!optIn.includes(r.component), `${r.key} shows for an opt-in child that is not selected`);
  }
  // The offered package checks bring their rows, the index download switch included.
  const keys = shown.map((r) => r.key);
  assert.ok(keys.includes("security.deps.install_wait_ms") && keys.includes("security.deps.index_download"), keys.join());
  // Every child the card has rows for is offered or opt-in.
  for (const r of CODE_SECURITY_SETTINGS) {
    assert.ok(offered.includes(r.component) || optIn.includes(r.component), `${r.key}: ${r.component} is in neither list this test pins`);
  }
  // A block that names security.scan.custom brings its two rows back.
  const named = codeSecurityRows(legacy, [...offered, "security.scan.custom"]).map((r) => r.key);
  assert.ok(named.includes("security.custom.schedule_hours") && named.includes("security.custom.pause_on_battery"), named.join());
  // A block that removes security.deps hides its rows.
  const noDeps = codeSecurityRows(legacy, offered.filter((id) => id !== "security.deps")).map((r) => r.key);
  assert.ok(!noDeps.includes("security.deps.install_wait_ms"));
});

test("on/off rows read, label, parse and patch booleans only", () => {
  const write = CODE_SECURITY_SETTINGS.find((r) => r.key === "security.secrets.write_check")!;
  const cap = CODE_SECURITY_SETTINGS.find((r) => r.key === "security.secrets.postwrite_cap_kib")!;
  assert.equal(codeSecurityValue({ Security: { Secrets: { WriteCheck: false } } }, write), false);
  assert.equal(codeSecurityValue({ Security: { Secrets: { WriteCheck: "false" } } }, write), null);
  assert.equal(codeSecurityValue({ Security: { Secrets: { PostWriteCapKiB: 16 } } }, cap), null, "16 KiB is the hook's fixed cap");
  assert.equal(codeSecurityOptionLabel(write, true), "On (default)");
  assert.equal(codeSecurityOptionLabel(write, false), "Off");
  assert.equal(codeSecurityOptionLabel(cap, 64), "64 KiB (scans less)");
  assert.equal(codeSecurityOptionLabel(cap, 256), "256 KiB (default)");
  assert.equal(codeSecurityParse(write, "false"), false);
  assert.equal(codeSecurityParse(cap, "256"), 256);
  assert.equal(codeSecurityParse(cap, "1024"), null);
  assert.deepEqual(codeSecurityPatch(write, true, false), { key: "security.secrets.write_check", value: false, was: true });
  assert.equal(codeSecurityPatch(write, true, true), null);
});

test("named-choice rows offer today's value first and stricter ones only (lane LEFT-SEC)", () => {
  const row = (k: string) => CODE_SECURITY_SETTINGS.find((r) => r.key === k)!;
  const sev = row("security.scanning.min_blocking_severity");
  assert.deepEqual(sev.values, ["high", "medium", "low"], "critical (looser than today) is not offered");
  assert.equal(codeSecurityValue({ Security: { Scanning: { MinBlockingSeverity: "medium" } } }, sev), "medium");
  assert.equal(codeSecurityValue({ Security: { Scanning: { MinBlockingSeverity: "critical" } } }, sev), null);
  assert.equal(codeSecurityOptionLabel(sev, "high"), "High (default)");
  assert.equal(codeSecurityParse(sev, "low"), "low");
  assert.deepEqual(codeSecurityPatch(sev, "high", "low"), { key: "security.scanning.min_blocking_severity", value: "low", was: "high" });
  const trust = row("security.trust.prelaunch");
  assert.deepEqual(trust.values, ["warn", "ask"]);
  assert.equal(codeSecurityOptionLabel(trust, "ask"), "Always ask");
  for (const k of ["security.deps.unknown_action", "security.deps.online_unknown_action"]) {
    assert.deepEqual(row(k).values, ["default", "ask", "deny"], k);
    assert.equal(row(k).defaultValue, "default", k);
  }
  assert.equal(row("security.scanning.quick_scan_budget_s").defaultValue, 2, "today's fixed 2 s budget is the default");
  assert.equal(row("security.scanning.max_scan_staleness_min").defaultValue, 0);
  assert.equal(codeSecurityOptionLabel(row("security.scanning.max_scan_staleness_min"), 0), "Off (default)");
  assert.equal(row("security.scanning.reflog_hold_max_age_days").defaultValue, 0);
  assert.equal(row("security.scanning.reflog_hold_max_entries").defaultValue, 0);
});

test("the schedule row says when its loop starts (PT-32)", () => {
  // The rows show as soon as a [components] block selects the child, but the
  // daemon starts the schedule loop only at its own start: the help says so.
  const row = CODE_SECURITY_SETTINGS.find((r) => r.key === "security.custom.schedule_hours")!;
  assert.match(row.help, /starts when the daemon starts/);
  assert.match(row.help, /restart the daemon/);
  assert.match(row.help, /while it runs, a change here applies within 15 minutes/);
});
