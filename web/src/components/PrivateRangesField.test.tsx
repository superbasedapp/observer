// Component test of the hosted private-range setting (decision SBXD-7,
// web/src/components/sandboxHosted/PrivateRangesField.tsx): it renders
// nothing for a daemon that predates the keys, offers a per-provider choice
// only where the daemon says the provider can deny, says the others cannot,
// keeps internal names under "Technical details", and goes read-only under
// an organization pin.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import type { SandboxHostedConfig } from "@/components/SandboxHostedPanel";
import { PrivateRangesField, type HostedPrivateRanges } from "@/components/sandboxHosted/PrivateRangesField";

const provider = { region: "", template: "", box_binary: "" };
const base: SandboxHostedConfig = {
  min_session_minutes: 30,
  key_custody: "home_relay",
  memory_images: "avoid",
  checkpoint_minutes: 5,
  max_run_minutes: 60,
  daily_box_minutes: 240,
  e2b: provider,
  modal: provider,
  vercel: provider,
  docker: provider,
};
const drivers = [
  { id: "e2b", table: "e2b", name: "E2B" },
  { id: "modal", table: "modal", name: "Modal" },
];
const withRanges = (r: HostedPrivateRanges) => ({ ...base, ...r }) as SandboxHostedConfig;
const render = (value: SandboxHostedConfig, pinned = new Set<string>(), writable = true) =>
  renderToStaticMarkup(<PrivateRangesField value={value} drivers={drivers} pinned={pinned} writable={writable} onChange={() => {}} />);

test("private ranges: nothing for a daemon that predates the keys", () => {
  assert.equal(render(base), "");
});

test("private ranges: off by default, a choice only for a provider that can deny", () => {
  const html = render(withRanges({ allow_private_ranges: false, private_range_overrides: { e2b: "follow" }, private_range_deny_capable: ["e2b"] }));
  assert.match(html, /Let a box on the internet setting reach private network addresses/);
  assert.doesNotMatch(html.match(/<input[^>]*type="checkbox"[^>]*>/)?.[0] ?? "", /checked/);
  assert.match(html, /E2B: private network addresses/);
  assert.doesNotMatch(html, /Modal: private network addresses/);
  assert.match(html, /Modal: the provider takes no rule that would refuse these ranges/);
  // Internal names sit only in the technical tooltip, never in the text.
  const text = html.replace(/<[^>]+>/g, " ");
  assert.doesNotMatch(text, /allow_private_ranges/);
});

test("private ranges: an organization pin makes it read-only", () => {
  const html = render(withRanges({ allow_private_ranges: false, private_range_deny_capable: ["e2b"] }), new Set(["hosted.allow_private_ranges"]));
  assert.match(html.match(/<input[^>]*type="checkbox"[^>]*>/)?.[0] ?? "", /disabled/);
  assert.match(html, /Set by your organization/);
});
