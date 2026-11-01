import assert from "node:assert/strict";
import test from "node:test";

import { hostsLabel, isolationWords, limitLabel, readyToAccept, runProjectOptions, selfTestWords, verdictWords } from "./customScanners.ts";

// Security Phase D3: the Scanners card's pure helpers.

test("the child-process picker names its per-OS unit", () => {
  assert.equal(limitLabel("child_processes", "tasks"), "Child processes, counted in tasks");
  assert.equal(limitLabel("child_processes", "processes"), "Child processes, counted in processes");
  assert.equal(limitLabel("memory_mib", "tasks"), "Memory (MiB)");
});

test("a run is clean only with a passed self-test", () => {
  assert.equal(selfTestWords(undefined, false).tone, "warn");
  assert.match(selfTestWords({ ran: false, passed: false }, true).text, /unknown/);
  assert.equal(selfTestWords({ ran: true, passed: true }, true).tone, "ok");
  const failed = selfTestWords({ ran: true, passed: false, missing: ["G703"] }, true);
  assert.equal(failed.tone, "danger");
  assert.match(failed.text, /G703/);
});

test("the run line says isolated or why not, and the containment label", () => {
  const base = { driver: "custom:x", verdict: { Outcome: "findings", Reason: "" }, findings: 1, refused: 0, closed: 0, runner_outcome: "ok" };
  assert.equal(
    isolationWords({ ...base, isolation: "isolation.oneshot", containment: { Rung: "pid_namespace", Contained: true, Label: "contained (isolation pid namespace)" } }),
    "isolated (isolation.oneshot); contained (isolation pid namespace)",
  );
  assert.match(
    isolationWords({ ...base, not_isolated_why: "the network is needed", containment: { Rung: "process_group", Contained: false, Label: "not contained (process group kill only, no sweep)" } }),
    /^not isolated: the network is needed; not contained/,
  );
  assert.equal(verdictWords({ ...base, verdict: { Outcome: "unknown", Reason: "no_self_test" }, containment: { Rung: "", Contained: false, Label: "" } }), "unknown (no self test)");
});

test("accept needs a shown digest", () => {
  assert.equal(readyToAccept(null), false);
  const p = { ManifestSHA256: "a".repeat(64) } as Parameters<typeof readyToAccept>[0];
  assert.equal(readyToAccept(p), true);
});

test("declared hosts are said to be not enforced, in the picker and on the run line", () => {
  assert.match(hostsLabel(["semgrep.dev"]), /semgrep\.dev \(not enforced: the scanner can reach any host/);
  const base = { driver: "custom:x", verdict: { Outcome: "findings", Reason: "" }, findings: 1, refused: 0, closed: 0, runner_outcome: "ok" };
  const line = isolationWords({
    ...base,
    not_isolated_why: "the manifest declares network hosts",
    network: "network: the manifest declares the hosts semgrep.dev, and they are not enforced: the scanner can reach any host",
    containment: { Rung: "cgroup_v2", Contained: true, Label: "contained (per-run cgroup v2)" },
  });
  assert.match(line, /contained \(per-run cgroup v2\); network: .* not enforced/);
});

test("the run picker offers only known projects, nothing until one is chosen", () => {
  const opts = runProjectOptions([{ id: "/home/u/app", label: "app" }]);
  assert.deepEqual(opts[0], { value: "", label: "Choose a project" });
  assert.deepEqual(opts[1], { value: "/home/u/app", label: "app (/home/u/app)" });
  assert.equal(runProjectOptions([]).length, 1);
});
