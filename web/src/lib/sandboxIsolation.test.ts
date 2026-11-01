import { test } from "node:test";
import assert from "node:assert/strict";
import {
  captureLabel,
  defaultIsolationChoice,
  degradedLabel,
  isolationChoiceSummary,
  isolationOptions,
  isolationSummary,
  launchBackend,
  runPillLabel,
  ISOLATION_AUTO,
  ISOLATION_NONE,
} from "./sandboxIsolation.ts";
import type { SandboxAvailability, SandboxBackendAvail } from "./types.ts";

const bwrap: SandboxBackendAvail = {
  id: "bwrap",
  label: "Bubblewrap",
  class: "process",
  location: "local",
  maturity: "beta",
  available: true,
  beta: false,
  capture_by_tier: { internet: "full (gateway-guarded)", host: "proxy_and_transcripts" },
  component: "terminals.sandbox",
};

test("captureLabel names the gateway-guarded case", () => {
  assert.equal(captureLabel("full", "C6"), "full (gateway-guarded)");
  assert.equal(captureLabel("full", "C5"), "full");
  assert.equal(captureLabel("transcripts_only", "C3"), "transcripts only");
  assert.equal(captureLabel(undefined, undefined), "capture not recorded");
});

test("the picker lists None, Automatic and the offered rows, planned rows left out", () => {
  const probe: SandboxAvailability = {
    available: true,
    default_on: false,
    backends: [bwrap, { ...bwrap, id: "oci-runc", label: "Docker or Podman", class: "container", maturity: "planned", available: false }],
  };
  const opts = isolationOptions(probe);
  assert.deepEqual(opts.map((o) => o.id), [ISOLATION_NONE, ISOLATION_AUTO, "bwrap"]);
  assert.equal(opts[1].disabled, false);
  assert.equal(opts[2].disabled, false);
});

test("an unavailable row stays visible and disabled with its reason", () => {
  const probe: SandboxAvailability = {
    available: false,
    default_on: false,
    backends: [{ ...bwrap, available: false, reason: "bwrap is not installed" }],
  };
  const opts = isolationOptions(probe);
  assert.equal(opts[2].disabled, true);
  assert.equal(opts[2].reason, "bwrap is not installed");
});

test("an older daemon without backends[] gets the shipped sandbox entry", () => {
  const opts = isolationOptions({ available: true, default_on: false, backend: "bwrap" });
  assert.deepEqual(opts.map((o) => o.id), [ISOLATION_NONE, "bwrap"]);
  assert.equal(isolationOptions(null).length, 1);
});

test("the summary chip says class, network, capture and beta", () => {
  assert.equal(isolationSummary(bwrap, "internet"), "process sandbox, network internet, capture full (gateway-guarded)");
  assert.equal(isolationSummary({ ...bwrap, beta: true }, "proxy_only"), "process sandbox, network proxy only, beta");
  assert.equal(isolationSummary(undefined, "internet"), null);
});

test("the run pill reads the run's recorded evidence", () => {
  assert.equal(
    runPillLabel({ class: "process", backend: "bwrap", egress_tier: "internet", capture_level: "full", capture_rule: "C6", verification: "live" }),
    "bwrap (process sandbox), network internet, capture full (gateway-guarded)",
  );
  assert.equal(runPillLabel({ class: "process", capture_level: "transcripts_only", capture_rule: "C3", verification: "doc" }), "process sandbox, capture transcripts only, beta");
  assert.equal(runPillLabel({ class: "none" }), null);
  assert.equal(runPillLabel(undefined), null);
});

test("the run pill says when capture was lowered after launch", () => {
  const base = { class: "process", backend: "bwrap", capture_level: "full", capture_rule: "C2", verification: "live" };
  assert.equal(
    runPillLabel({ ...base, capture_degraded: true, capture_causes: ["refused", "heartbeat_missed"] }),
    "bwrap (process sandbox), capture full, capture degraded (events refused, heartbeats missed)",
  );
  assert.equal(
    runPillLabel({ ...base, capture_degraded: true, capture_causes: ["dropped", "hooks_drifted"] }),
    "bwrap (process sandbox), capture full, capture no longer complete (events lost, hooks changed in the box)",
  );
  assert.equal(degradedLabel({ ...base, capture_degraded: true }), "capture degraded");
  assert.equal(degradedLabel({ ...base, capture_causes: ["refused"] }), null);
  assert.equal(degradedLabel(undefined), null);
});

// Lane SBX-P3B (rulings P-062 and P-067): Automatic is the default entry
// and names no backend; a beta row is offered, labelled, never the default,
// and named in the launch body only when chosen.
test("Automatic is the default and a beta row runs only when chosen", () => {
  const oci = { ...bwrap, id: "oci-runc", label: "Docker or Podman", class: "container", maturity: "preview", available: true, beta: true };
  const probe: SandboxAvailability = {
    available: false,
    verdict: "beta_not_chosen",
    reason: "oci-runc is available but not chosen",
    default_on: false,
    backends: [{ ...bwrap, available: false, reason: "not enabled" }, oci],
  };
  const opts = isolationOptions(probe);
  const auto = opts.find((o) => o.id === ISOLATION_AUTO)!;
  assert.equal(auto.disabled, true);
  assert.equal(auto.reason, "oci-runc is available but not chosen");
  const row = opts.find((o) => o.id === "oci-runc")!;
  assert.equal(row.beta, true);
  assert.equal(row.disabled, false);
  // Nothing non-beta is enabled, so the picker starts on no entry rather
  // than a beta row.
  assert.equal(defaultIsolationChoice(opts), undefined);
  assert.equal(defaultIsolationChoice(isolationOptions({ available: true, default_on: false, backend: "bwrap", backends: [bwrap, oci] })), ISOLATION_AUTO);
  assert.equal(launchBackend(ISOLATION_AUTO), undefined);
  assert.equal(launchBackend(ISOLATION_NONE), undefined);
  assert.equal(launchBackend("oci-runc"), "oci-runc");
});

test("the Automatic chip names the row the daemon would take", () => {
  const probe: SandboxAvailability = { available: true, default_on: false, backend: "bwrap", egress: "internet", backends: [bwrap] };
  assert.equal(isolationChoiceSummary(probe, ISOLATION_AUTO), "Automatic: process sandbox, network internet, capture full (gateway-guarded)");
  assert.equal(isolationChoiceSummary(probe, "bwrap"), "process sandbox, network internet, capture full (gateway-guarded)");
  assert.equal(isolationChoiceSummary({ ...probe, available: false }, ISOLATION_AUTO), null);
  assert.equal(isolationChoiceSummary(null, ISOLATION_AUTO), null);
});
