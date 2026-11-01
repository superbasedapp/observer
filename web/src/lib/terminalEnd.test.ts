// Pins the dashboard's named end lines (Windows 11 Pro run 4, N3): one line
// per reason, the same words as the CLI's (internal/termrun/endreason.go).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { TERMINAL_END_LINES, terminalEndLine } from "./terminalEnd.ts";

test("each end reason has its own named line with the exit code", () => {
  assert.equal(terminalEndLine("dashboard_stop", 1), "the run ended: stopped from the dashboard (Stop & close) (exit code 1)");
  assert.equal(terminalEndLine("console_closed", 3221225786), "the run ended: the console window was closed (exit code 3221225786)");
  assert.equal(terminalEndLine("child_exit", 7), "the run ended: the tool exited (exit code 7)");
  assert.equal(terminalEndLine("process_gone", null), "the run ended: the run's process is gone (ended outside Observer); its exit code is not known");
  assert.equal(terminalEndLine(undefined, 0), "the run ended (exit code 0)");
  assert.equal(terminalEndLine("something-new", null), "the run ended");
  const lines = Object.values(TERMINAL_END_LINES);
  assert.equal(new Set(lines).size, lines.length, "two reasons share a line");
});

test("the lines match the CLI's table word for word", () => {
  const go = readFileSync(new URL("../../../internal/termrun/endreason.go", import.meta.url), "utf8");
  const table = go.slice(go.indexOf("var endLines"), go.indexOf("}", go.indexOf("var endLines")));
  for (const line of Object.values(TERMINAL_END_LINES)) {
    assert.ok(table.includes(JSON.stringify(line)), `the Go table lacks ${JSON.stringify(line)}`);
  }
  assert.equal((table.match(/: +"/g) ?? []).length, Object.keys(TERMINAL_END_LINES).length, "the two tables have the same rows");
});
