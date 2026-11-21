// Component tests of the sandbox card's Backends list: the Enabled
// checkboxes write the backends key, up/down reorder only the enabled rows,
// and a row says whether enabling it would make it run here.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { SandboxBackendsList } from "@/components/SandboxSettingsCard";
import type { SandboxBackendAvail } from "@/lib/types";

const row = (over: Partial<SandboxBackendAvail>): SandboxBackendAvail => ({
  id: "bwrap",
  label: "Bubblewrap",
  class: "process",
  location: "local",
  maturity: "beta",
  available: true,
  beta: false,
  capture_by_tier: {},
  component: "terminals.sandbox",
  ...over,
});

const rows = [
  row({}),
  row({ id: "landlock", label: "Landlock only", available: false, verdict: "disabled_by_config", when_enabled_available: true }),
  row({ id: "mxc", label: "MXC AppContainer", available: false, verdict: "disabled_by_config", when_enabled_reason: "this backend does not run on linux" }),
  row({ id: "oci-runc", label: "Docker or Podman", available: false, verdict: "disabled_by_config", when_enabled_verdict: "module_inactive", when_enabled_reason: "the terminals.sandbox.oci component is not selected on this node" }),
  row({ id: "e2b", label: "E2B", maturity: "planned", available: false, phase: "P7" }),
];

// input returns the checkbox tag for a backend label (attribute order is
// React's, so the tests look for attributes, not a fixed sequence).
function input(html: string, label: string): string {
  const m = html.match(new RegExp(`<input[^>]*aria-label="Enable ${label}"[^>]*>`));
  assert.ok(m, `no checkbox for ${label}`);
  return m[0];
}

function render(order: string[]): string {
  return renderToStaticMarkup(
    <MemoryRouter>
      <SandboxBackendsList backends={rows} order={order} egress="internet" writable onOrder={() => {}} />
    </MemoryRouter>,
  );
}

test("every offered backend has an Enabled checkbox matching the enabled list", () => {
  const html = render(["bwrap"]);
  assert.match(html, /id="sandbox-backends"/);
  assert.match(input(html, "Bubblewrap"), /checked=""/);
  assert.doesNotMatch(input(html, "Landlock only"), /checked|disabled/);
  // The only enabled backend cannot be unticked (an empty list means bwrap).
  assert.match(input(html, "Bubblewrap"), /disabled=""/);
  assert.doesNotMatch(input(render(["bwrap", "landlock"]), "Bubblewrap"), /disabled/);
  // Planned rows are listed, never offered.
  assert.doesNotMatch(html, /Enable E2B/);
  assert.match(html, /Not offered yet: E2B \(P7\)/);
});

test("a row says whether enabling it would make it run here", () => {
  const html = render(["bwrap"]);
  assert.match(html, /not enabled; runs here once enabled/);
  assert.match(html, /this backend does not run on linux/);
  // A backend whose module is not installed says so and links to Components.
  assert.match(html, /the terminals\.sandbox\.oci component is not selected on this node<\/span><a [^>]*href="\/settings\/components"[^>]*>Install its module<\/a>/);
  // Ticked in the draft but not saved yet.
  assert.match(render(["bwrap", "landlock"]), /runs here once saved/);
});

test("up and down are offered only among the enabled backends", () => {
  assert.doesNotMatch(render(["bwrap"]), /aria-label="Prefer/);
  const two = render(["landlock", "bwrap"]);
  assert.match(two, /<button[^>]*disabled=""[^>]*aria-label="Prefer landlock"/);
  assert.match(two, /aria-label="Prefer bwrap"/);
  assert.doesNotMatch(two, /aria-label="Prefer mxc"/);
});
