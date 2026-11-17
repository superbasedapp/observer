import { test } from "node:test";
import assert from "node:assert/strict";
import {
  backendNotes,
  backendState,
  captureLabel,
  gatewayModeLabel,
  unavailableRows,
  defaultIsolationChoice,
  degradedLabel,
  isolationChoiceSummary,
  isolationOptions,
  isolationSummary,
  launchBackend,
  runPillLabel,
  seccompRunLabel,
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

test("backendNotes renders the daemon's sentences in order: prerequisite, hint, disclosures", () => {
  assert.deepEqual(backendNotes(undefined), []);
  assert.deepEqual(backendNotes(bwrap), []);
  assert.deepEqual(
    backendNotes({ ...bwrap, prerequisite: "P", hint: "H", disclosures: [{ id: "a", text: "D1" }, { id: "b", text: "" }, { id: "c", text: "D2" }] }),
    ["P", "H", "D1", "D2"],
  );
});

test("gatewayModeLabel names the closed modes and passes an unknown one through", () => {
  assert.equal(gatewayModeLabel(undefined), "");
  assert.equal(gatewayModeLabel("managed_local"), "Observer's private gateway");
  assert.equal(gatewayModeLabel("external"), "your own gateway");
  assert.equal(gatewayModeLabel("org_shared"), "org shared");
});

test("isolationSummary names a row's gateway", () => {
  assert.equal(
    isolationSummary({ ...bwrap, class: "container", gateway_mode: "external", beta: true }, "proxy_only"),
    "container, network proxy only, gateway: your own gateway, beta",
  );
});

test("unavailableRows lists offered rows that cannot run, never planned ones", () => {
  const probe = {
    available: true,
    default_on: false,
    backends: [
      bwrap,
      { ...bwrap, id: "x", label: "X", available: false, reason: "why" },
      { ...bwrap, id: "y", label: "Y", available: false, verdict: "v" },
      { ...bwrap, id: "z", label: "Z", available: false, maturity: "planned" },
      {
        ...bwrap,
        id: "w",
        label: "W",
        available: false,
        reason: "docker missing",
        prerequisite: "P",
        disclosures: [{ id: "a", text: "D3" }],
      },
    ],
  } as SandboxAvailability;
  assert.deepEqual(unavailableRows(probe), [
    { id: "x", label: "X", reason: "why", notes: [] },
    { id: "y", label: "Y", reason: "v", notes: [] },
    // An unavailable row carries its served prerequisite and disclosures
    // beside its reason (audit finding O4-A8).
    { id: "w", label: "W", reason: "docker missing", notes: ["P", "D3"] },
  ]);
  assert.deepEqual(unavailableRows(null), []);
  // A row that only needs enabling or its module is counted by the picker's
  // own link lines, not listed here; one that is off AND unsupported names
  // the real blocker.
  const off = { ...bwrap, available: false, verdict: "disabled_by_config", reason: "not in the enabled backends list" };
  assert.deepEqual(
    unavailableRows({
      available: true,
      default_on: false,
      backends: [
        { ...off, id: "ll", label: "LL", when_enabled_available: true },
        { ...off, id: "oci", label: "OCI", when_enabled_verdict: "module_inactive", when_enabled_reason: "module" },
        { ...off, id: "mxc", label: "MXC", when_enabled_verdict: "unsupported_platform", when_enabled_reason: "not on linux" },
      ],
    } as SandboxAvailability),
    [{ id: "mxc", label: "MXC", reason: "not on linux", notes: [] }],
  );
});

test("the run pill names the seccomp state a key-on run got", () => {
  const base = { class: "process", backend: "bwrap", capture_level: "full", capture_rule: "C2", verification: "live" };
  assert.equal(runPillLabel({ ...base, seccomp: "observer_default" }), "bwrap (process sandbox), capture full, seccomp filter observer_default");
  assert.equal(
    runPillLabel({ ...base, backend: "seatbelt", seccomp: "not_applicable" }),
    "seatbelt (process sandbox), capture full, seccomp not applicable: not filtered by Observer",
  );
  for (const s of ["off", "none", "engine_default", ""]) assert.equal(seccompRunLabel({ ...base, seccomp: s }), null);
  // The strace switch (lane ptrace) names the ground the launch recorded.
  assert.match(seccompRunLabel({ ...base, seccomp: "observer_seize_pidns" }) ?? "", /observer_seize_pidns, strace allowed \(the sandbox has its own process list\)/);
  assert.match(seccompRunLabel({ ...base, seccomp: "observer_seize_yama" }) ?? "", /observer_seize_yama, strace allowed \(Yama limits it/);
});

test("backendState tells a backend that only needs enabling from one that cannot run here", () => {
  assert.deepEqual(backendState(bwrap), { state: "available", reason: "" });
  const off = { ...bwrap, available: false, verdict: "disabled_by_config", reason: "not in the enabled backends list" };
  assert.equal(backendState({ ...off, when_enabled_available: true }).state, "not_enabled");
  // Off AND unsupported: the real blocker is named, not "not enabled".
  assert.deepEqual(backendState({ ...off, when_enabled_verdict: "unsupported_platform", when_enabled_reason: "this backend does not run on windows" }), {
    state: "unavailable",
    reason: "this backend does not run on windows",
  });
  // An older daemon with no hypothetical keeps its own reason.
  assert.deepEqual(backendState(off), { state: "unavailable", reason: "not in the enabled backends list" });
  assert.deepEqual(backendState({ ...bwrap, available: false, verdict: "probe_failed", reason: "no bwrap" }), { state: "unavailable", reason: "no bwrap" });
});

test("the picker marks a backend that runs here once enabled as not enabled", () => {
  const off = { ...bwrap, id: "landlock", label: "Landlock", available: false, verdict: "disabled_by_config", reason: "not in the enabled backends list" };
  const opts = isolationOptions({
    available: true,
    default_on: false,
    backend: "bwrap",
    backends: [bwrap, { ...off, when_enabled_available: true }, { ...off, id: "mxc", when_enabled_reason: "this backend does not run on linux" }],
  });
  const ll = opts.find((o) => o.id === "landlock");
  assert.equal(ll?.disabled, true);
  assert.equal(ll?.notEnabled, true);
  const mxc = opts.find((o) => o.id === "mxc");
  assert.equal(mxc?.notEnabled, false);
  assert.equal(mxc?.reason, "this backend does not run on linux");
  assert.equal(opts.find((o) => o.id === "bwrap")?.notEnabled, false);
});

test("a backend whose module is not installed needs the module, enabled or not", () => {
  const reason = "the terminals.sandbox.oci component is not selected on this node; select it in Settings > Components";
  const off = { ...bwrap, id: "oci-runc", available: false, verdict: "disabled_by_config", when_enabled_verdict: "module_inactive", when_enabled_reason: reason };
  assert.deepEqual(backendState(off), { state: "needs_module", reason });
  assert.deepEqual(backendState({ ...bwrap, available: false, verdict: "module_inactive", reason }), { state: "needs_module", reason });
  const o = isolationOptions({ available: true, default_on: false, backend: "bwrap", backends: [bwrap, off] }).find((x) => x.id === "oci-runc");
  assert.equal(o?.needsModule, true);
  assert.equal(o?.notEnabled, false);
});
