import assert from "node:assert/strict";
import test from "node:test";

import {
  MACHINE_INDEPENDENT_COPY,
  NOT_ROUTED_COPY,
  NO_PROJECT_FOLDER_COPY,
  ROUTED_COPY,
  guiLaunchSummary,
  guiLaunchedToast,
  guiNotGroundedReason,
  guiRoutingSentence,
  type GUICopyRow,
  type GUIRoutingVerdict,
} from "./guiLaunchCopy.ts";

const row = (over: Partial<GUICopyRow> = {}): GUICopyRow => ({
  label: "OpenCode Desktop",
  wrap_kind: "child_env",
  project_dir_argv: true,
  grounded: true,
  ...over,
});

// One case per routing row: (wrap_kind, verdict) -> sentence.
const routingCases: Array<{ name: string; over?: Partial<GUICopyRow>; verdict?: GUIRoutingVerdict | null; want: string }> = [
  {
    name: "WSL interop: child_env does NOT reach the app, and the line says so",
    verdict: { routing_reaches_app: false, routing_reason: "interop_env_not_propagated" },
    want: NOT_ROUTED_COPY.interop_env_not_propagated,
  },
  {
    name: "native launch: child_env reaches the app",
    verdict: { routing_reaches_app: true },
    want: ROUTED_COPY.child_env,
  },
  {
    name: "no verdict (older daemon): child_env claims NOTHING",
    verdict: null,
    want: "",
  },
  { name: "packaged app", verdict: { routing_reaches_app: false, routing_reason: "packaged_app_no_env" }, want: NOT_ROUTED_COPY.packaged_app_no_env },
  { name: "hand-off launcher", verdict: { routing_reaches_app: false, routing_reason: "handoff_launcher" }, want: NOT_ROUTED_COPY.handoff_launcher },
  { name: "no proxy url", verdict: { routing_reaches_app: false, routing_reason: "no_proxy_url" }, want: NOT_ROUTED_COPY.no_proxy_url },
  { name: "unknown reason says nothing", verdict: { routing_reaches_app: false, routing_reason: "teleport_failed" }, want: "" },
  {
    name: "config_write with a verdict",
    over: { wrap_kind: "config_write" },
    verdict: { routing_reaches_app: false, routing_reason: "config_write" },
    want: NOT_ROUTED_COPY.config_write,
  },
  { name: "config_write without a verdict is machine-independent", over: { wrap_kind: "config_write" }, want: MACHINE_INDEPENDENT_COPY.config_write },
  { name: "none without a verdict is machine-independent", over: { wrap_kind: "none" }, want: MACHINE_INDEPENDENT_COPY.none },
  {
    name: "none with a verdict",
    over: { wrap_kind: "none" },
    verdict: { routing_reaches_app: false, routing_reason: "no_wrap_mechanism" },
    want: NOT_ROUTED_COPY.no_wrap_mechanism,
  },
];
for (const c of routingCases) {
  test(`guiRoutingSentence: ${c.name}`, () => {
    assert.equal(guiRoutingSentence(row(c.over), c.verdict), c.want);
  });
}

test("the not-routed reasons cover the Go WrapReason vocabulary", () => {
  // internal/guilaunch WrapReason values (every non-empty one).
  for (const reason of [
    "interop_env_not_propagated",
    "packaged_app_no_env",
    "handoff_launcher",
    "no_proxy_url",
    "no_routing_vars",
    "config_write",
    "no_wrap_mechanism",
  ]) {
    assert.ok(NOT_ROUTED_COPY[reason], reason);
  }
});

test("a child_env row never claims routing without a confirming verdict", () => {
  assert.ok(!("child_env" in MACHINE_INDEPENDENT_COPY));
  assert.ok(!guiRoutingSentence(row(), undefined).includes("proxy address is set"));
  assert.ok(
    !guiRoutingSentence(row(), { routing_reaches_app: false, routing_reason: "interop_env_not_propagated" }).includes(
      "proxy address is set when",
    ),
  );
});

test("guiLaunchSummary joins the folder fact and the routing fact", () => {
  assert.equal(
    guiLaunchSummary(row({ project_dir_argv: false }), { routing_reaches_app: true }),
    `${NO_PROJECT_FOLDER_COPY} ${ROUTED_COPY.child_env}`,
  );
  assert.equal(guiLaunchSummary(row({ project_dir_argv: false }), null), NO_PROJECT_FOLDER_COPY);
  assert.equal(guiLaunchSummary(row(), null), "");
});

const toastCases: Array<{ name: string; r: Parameters<typeof guiLaunchedToast>[0]; routed: boolean }> = [
  { name: "routed per the launch verdict", r: { label: "App", pid: 1, wrap_applied: true, routing_reaches_app: true }, routed: true },
  { name: "not routed (WSL interop)", r: { label: "App", pid: 1, wrap_applied: false, routing_reaches_app: false }, routed: false },
  { name: "older daemon falls back to wrap_applied", r: { label: "App", pid: 1, wrap_applied: true }, routed: true },
];
for (const c of toastCases) {
  test(`guiLaunchedToast: ${c.name}`, () => {
    assert.equal(guiLaunchedToast(c.r).includes("routed through the superbased proxy"), c.routed);
  });
}

test("the copy never carries engineering jargon", () => {
  const all = [
    ...Object.values(ROUTED_COPY),
    ...Object.values(NOT_ROUTED_COPY),
    ...Object.values(MACHINE_INDEPENDENT_COPY),
    NO_PROJECT_FOLDER_COPY,
    guiNotGroundedReason(row()),
  ].join(" ");
  for (const word of ["grounded", "Routability", "native_exempt", "wrap", "argv", "base URL", "WSLENV", "env "]) {
    assert.ok(!all.includes(word), word);
  }
});

test("guiNotGroundedReason names the app and the consequence", () => {
  assert.equal(
    guiNotGroundedReason({ label: "Kiro" }),
    "superbased doesn't know where Kiro is installed yet, so it can't launch it from here.",
  );
});
