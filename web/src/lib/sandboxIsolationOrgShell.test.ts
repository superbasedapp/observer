import { test } from "node:test";
import assert from "node:assert/strict";
import { isolationOptions, offeredHere, unavailableRows } from "./sandboxIsolation.ts";
import type { SandboxAvailability, SandboxBackendAvail } from "./types.ts";

// The org-hosted row (lane G4, g1-design.md section 8.4): on a node whose
// organization publishes no gateway the probe answers
// org_gateway_not_offered and the picker omits the row; a node that is
// offered it but has not opted in sees it disabled with its reason.
const orgRow = (verdict: string | undefined, available: boolean): SandboxBackendAvail => ({
  id: "openshell-org",
  label: "OpenShell (org-hosted)",
  class: "container",
  location: "remote",
  maturity: "beta",
  available,
  beta: true,
  verdict,
  reason: verdict ? "why" : undefined,
  capture_by_tier: {},
  component: "terminals.sandbox.openshell-org",
});

const probe = (b: SandboxBackendAvail): SandboxAvailability =>
  ({ available: true, verdict: "available", backend: "bwrap", backends: [b] }) as SandboxAvailability;

test("a row not offered here is left out of the picker and the unavailable list", () => {
  const b = orgRow("org_gateway_not_offered", false);
  assert.equal(offeredHere(b), false);
  assert.equal(isolationOptions(probe(b)).some((o) => o.id === "openshell-org"), false);
  assert.equal(unavailableRows(probe(b)).length, 0);
});

test("an offered row that is not opted in is shown disabled with its reason", () => {
  const b = orgRow("laptop_relay_not_opted_in", false);
  const opt = isolationOptions(probe(b)).find((o) => o.id === "openshell-org");
  assert.ok(opt);
  assert.equal(opt.disabled, true);
  assert.equal(unavailableRows(probe(b)).length, 1);
});
