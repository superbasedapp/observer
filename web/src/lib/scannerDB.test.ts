import assert from "node:assert/strict";
import test from "node:test";

import { scannerDBAcceptLabel, scannerDBLine, scannerDBStage, type ScannerDBStatus } from "./scannerDB.ts";

function status(over: Partial<ScannerDBStatus>): ScannerDBStatus {
  return {
    accepted: false,
    approx_mb: 300,
    source: "osv-vulnerabilities.storage.googleapis.com",
    text: "",
    managed: false,
    blocked: "database_not_accepted",
    installed: 0,
    ...over,
  };
}

test("stage: managed, waiting and accepted; unknown reads null", () => {
  assert.equal(scannerDBStage(null), null);
  assert.equal(scannerDBStage(status({})), "waiting");
  assert.equal(scannerDBStage(status({ accepted: true, blocked: undefined })), "accepted");
  assert.equal(scannerDBStage(status({ managed: true })), "managed");
});

test("before the accept the line names the size, the source and that nothing is scanned", () => {
  const line = scannerDBLine(status({}));
  assert.ok(line.includes("about 300 MB"), line);
  assert.ok(line.includes("osv-vulnerabilities.storage.googleapis.com"), line);
  assert.ok(line.includes("not scanned"), line);
  assert.ok(!line.toLowerCase().includes("clean"), line);
  assert.equal(scannerDBAcceptLabel(status({})), "Accept and download about 300 MB");
});

test("after the accept the line says where and who", () => {
  const line = scannerDBLine(status({ accepted: true, accepted_at: "2026-10-21T09:00:00Z", accepted_on: "cli", by: "dev" }));
  assert.ok(line.includes("(cli, dev)") && line.includes("automatic"), line);
});
