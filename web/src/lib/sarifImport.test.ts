import { test } from "node:test";
import assert from "node:assert/strict";
import { byteLength, sarifReportLine, sarifUploadBody, sarifUploadCheck } from "./sarifImport.ts";

test("the client check refuses empty, oversize and non-object files", () => {
  assert.equal(sarifUploadCheck('{"version":"2.1.0","runs":[]}', 1 << 20), null);
  assert.match(sarifUploadCheck("  ", 1 << 20) ?? "", /empty/);
  assert.match(sarifUploadCheck("not json", 1 << 20) ?? "", /not JSON/);
  assert.match(sarifUploadCheck("[1,2]", 1 << 20) ?? "", /not a SARIF log/);
  assert.match(sarifUploadCheck('{"pad":"' + "x".repeat(2 << 20) + '"}', 1 << 20) ?? "", /over the 1 MB/);
});

test("the cap counts UTF-8 bytes, not characters", () => {
  assert.equal(byteLength("é"), 2);
  assert.match(sarifUploadCheck('{"a":"éé"}', 11) ?? "", /over/);
  assert.equal(sarifUploadCheck('{"a":"éé"}', 14), null);
});

test("the body carries the file's own text unchanged", () => {
  const file = '{ "version" : "2.1.0",\n  "runs": [] }';
  const body = sarifUploadBody('p"1', "gosec", file);
  assert.ok(body.endsWith(`"sarif":${file}}`));
  const parsed = JSON.parse(body) as { project: string; tool: string };
  assert.equal(parsed.project, 'p"1');
  assert.equal(parsed.tool, "gosec");
});

test("the report line says refused and truncated results", () => {
  const line = sarifReportLine({
    project_root_hash: "h", tool: "gosec", outcome: "partial", reason: "results_refused",
    findings: 3, new: 2, with_lineage: 1, refused: { outside_root: 2, no_location: 1 }, truncated: true,
  });
  assert.match(line, /^Imported 3 finding\(s\) from gosec \(2 new, 1 with an inferred AI-edit lineage\); outcome partial \(results refused\)\./);
  assert.match(line, / 3 result\(s\) refused\./);
  assert.match(line, /rest were not imported/);
});
