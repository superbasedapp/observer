import { test } from "node:test";
import assert from "node:assert/strict";
import { gatewayCell, gatewayMonthToDate, hasGatewayUsage, monthOf } from "./gatewayUsage.ts";

const NOW = new Date("2026-11-24T22:00:00Z");

test("the gateway column shows only when a host reports the count", () => {
  assert.equal(hasGatewayUsage([]), false);
  assert.equal(hasGatewayUsage([{ day: "2026-11-24" }]), false);
  assert.equal(hasGatewayUsage([{ day: "2026-11-24", aigw_requests: null }]), false);
  assert.equal(hasGatewayUsage([{ day: "2026-11-24" }, { day: "2026-11-23", aigw_requests: 0 }]), true);
});

test("month to date sums this UTC month's reported days only", () => {
  assert.equal(monthOf(NOW), "2026-11");
  const rows = [
    { day: "2026-11-24", aigw_requests: 120 },
    { day: "2026-11-23", aigw_requests: 80 },
    { day: "2026-11-22" },
    { day: "2026-10-31", aigw_requests: 5000 },
  ];
  assert.equal(gatewayMonthToDate(rows, NOW), 200);
  assert.equal(gatewayMonthToDate([{ day: "2026-10-31", aigw_requests: 5 }], NOW), null);
  assert.equal(gatewayMonthToDate([{ day: "2026-11-01", aigw_requests: 0 }], NOW), 0);
});

test("a day the host did not report is a dash, never a zero", () => {
  assert.equal(gatewayCell({ day: "2026-11-24" }), "-");
  assert.equal(gatewayCell({ day: "2026-11-24", aigw_requests: 0 }), "0");
  assert.equal(gatewayCell({ day: "2026-11-24", aigw_requests: 12345 }), "12,345");
});
