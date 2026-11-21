// Tests of the observe-only process findings grouping (processFindings.ts).

import { test } from "node:test";
import assert from "node:assert/strict";
import { groupProcessFindings } from "./processFindings.ts";
import type { ProcessFinding } from "./types.ts";

function f(over: Partial<ProcessFinding>): ProcessFinding {
  return {
    rule_id: "process.executable_from_tmp",
    severity: "warn",
    process_key: "k",
    session_id: "s",
    exe_basename: "db.test.exe",
    detail: "executable runs from a scratch location (tmp)",
    timestamp: "2026-11-03T10:00:00Z",
    ...over,
  };
}

test("groupProcessFindings folds identical findings and orders the groups", () => {
  const cases: Array<{ name: string; in: ProcessFinding[]; want: Array<[string, string, number, string]> }> = [
    { name: "empty", in: [], want: [] },
    {
      name: "same rule, exe and detail fold into one row with a count and the newest time",
      in: [
        f({ process_key: "a", timestamp: "2026-11-03T10:00:00Z" }),
        f({ process_key: "b", timestamp: "2026-11-03T12:00:00Z" }),
        f({ process_key: "c", timestamp: "2026-11-03T11:00:00Z" }),
      ],
      want: [["db.test.exe", "warn", 3, "2026-11-03T12:00:00Z"]],
    },
    {
      name: "a different detail is its own row",
      in: [f({ process_key: "a" }), f({ process_key: "b", detail: "executable runs from a scratch location (appdata/local/temp)" })],
      want: [
        ["db.test.exe", "warn", 1, "2026-11-03T10:00:00Z"],
        ["db.test.exe", "warn", 1, "2026-11-03T10:00:00Z"],
      ],
    },
    {
      name: "high before warn before info, then the larger count",
      in: [
        f({ exe_basename: "api.test.exe", severity: "info" }),
        f({ exe_basename: "db.test.exe" }),
        f({ exe_basename: "db.test.exe", process_key: "b" }),
        f({ exe_basename: "x.exe", severity: "high", rule_id: "process.shell_from_agent" }),
        f({ exe_basename: "rbac.test.exe" }),
      ],
      want: [
        ["x.exe", "high", 1, "2026-11-03T10:00:00Z"],
        ["db.test.exe", "warn", 2, "2026-11-03T10:00:00Z"],
        ["rbac.test.exe", "warn", 1, "2026-11-03T10:00:00Z"],
        ["api.test.exe", "info", 1, "2026-11-03T10:00:00Z"],
      ],
    },
    {
      name: "a group takes its strongest severity",
      in: [f({ severity: "info" }), f({ severity: "high", process_key: "b" })],
      want: [["db.test.exe", "high", 2, "2026-11-03T10:00:00Z"]],
    },
  ];
  for (const c of cases) {
    const got = groupProcessFindings(c.in).map((g) => [g.exe_basename ?? "", g.severity, g.count, g.last]);
    assert.deepEqual(got, c.want, c.name);
  }
});

test("groupProcessFindings lists a group's occurrences newest first", () => {
  const [g] = groupProcessFindings([
    f({ process_key: "a", timestamp: "2026-11-03T10:00:00Z" }),
    f({ process_key: "b", timestamp: "2026-11-03T12:00:00Z" }),
    f({ process_key: "c", timestamp: "2026-11-03T11:00:00Z" }),
  ]);
  assert.deepEqual(
    g.items.map((i) => i.process_key),
    ["b", "c", "a"],
  );
});
