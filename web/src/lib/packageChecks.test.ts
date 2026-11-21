import assert from "node:assert/strict";
import test from "node:test";

import {
  PACKAGE_CHECKS_ONLINE_KEY,
  packageChecksIndexDownloadNote,
  packageChecksIndexLine,
  packageChecksOnlinePatch,
  packageChecksStage,
  type PackageChecksStatus,
} from "./packageChecks.ts";

function status(over: Partial<PackageChecksStatus>): PackageChecksStatus {
  return { active: true, online: true, managed: false, accepted: false, text: "", not_set_up: true, index: [], ...over };
}

test("stage: inactive, waiting, on and offline", () => {
  assert.equal(packageChecksStage(null), "inactive");
  assert.equal(packageChecksStage(status({ active: false })), "inactive");
  assert.equal(packageChecksStage(status({})), "waiting");
  assert.equal(packageChecksStage(status({ accepted: true })), "on");
  assert.equal(packageChecksStage(status({ online: false, accepted: true })), "offline");
});

test("the online switch patch carries the current value", () => {
  assert.deepEqual(packageChecksOnlinePatch(true), { key: PACKAGE_CHECKS_ONLINE_KEY, value: false, was: true });
  assert.deepEqual(packageChecksOnlinePatch(false), { key: PACKAGE_CHECKS_ONLINE_KEY, value: true, was: false });
});

test("index lines never claim a list that is not installed", () => {
  assert.equal(packageChecksIndexLine({ kind: "security.malicious_packages", state: "not_installed" }), "malicious packages: not installed yet");
  assert.equal(
    packageChecksIndexLine({ kind: "security.popular_names", state: "installed", version: 3, freshness: "fresh" }),
    "popular names: version 3, fresh",
  );
  assert.equal(packageChecksIndexLine({ kind: "security.popular_names", state: "unreadable" }), "popular names: state unreadable");
});

test("the index download note shows only while the switch is off", () => {
  assert.equal(packageChecksIndexDownloadNote(null), null);
  assert.equal(packageChecksIndexDownloadNote(status({})), null, "an older daemon that does not report it reads on");
  assert.equal(packageChecksIndexDownloadNote(status({ index_download: true })), null);
  const off = packageChecksIndexDownloadNote(status({ index_download: false }));
  assert.ok(off && off.includes("index already on disk"), String(off));
  // It names the dashboard switch, not the config key (dashboard CLI parity).
  assert.ok(off.includes("Settings > Guard > Code security") && !off.includes("security.deps"), off);
});
