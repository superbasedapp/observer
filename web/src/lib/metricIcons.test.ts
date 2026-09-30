import { test } from "node:test";
import assert from "node:assert/strict";
import { METRIC_ICONS, metricIcon, type MetricKey } from "../../../shared/lib/metricIcons.ts";

// Two different metrics never share a glyph: the pre-WS6 defect was Coins /
// Bolt / Droplet / Sparkles reused across unrelated KPI tiles. Compared by
// component identity so a lucide alias of a glyph already in the table still
// counts as a clash.
test("every metric has a distinct icon", () => {
  const seen = new Map<unknown, string>();
  for (const [key, icon] of Object.entries(METRIC_ICONS)) {
    assert.ok(icon, `${key} has no icon`);
    const prev = seen.get(icon);
    assert.equal(prev, undefined, `${key} reuses the icon of ${prev}`);
    seen.set(icon, key);
  }
});

test("metricIcon reads the table", () => {
  for (const key of Object.keys(METRIC_ICONS) as MetricKey[]) {
    assert.equal(metricIcon(key), METRIC_ICONS[key]);
  }
});
