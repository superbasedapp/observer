import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

import {
  approvedServerCount,
  approvedServerRows,
  cellLabel,
  cellTier,
  chainLine,
  coverageGrid,
  coverageSummaryLine,
  coverageTally,
  coverageTier,
  effectiveLine,
  mcpAccessSectionState,
  relayLine,
  remoteLine,
  safeConnectURL,
  type MCPAccessCoverageRow,
  type MCPAccessResponse,
  type MCPAccessView,
} from "./mcpAccess.ts";

// The node Security page's "MCP access" section (Agent Access P10) renders
// GET /api/mcp-access/status. These pin the frame (loading / error /
// unavailable / disabled / on), the coverage-honesty tiering (a cell is never
// upgraded past what the matrix measured) and the wording of each line.

function row(client: string, transport: string, method: string, coverage: string, note = "n"): MCPAccessCoverageRow {
  return { client, transport, method, coverage, note };
}

function view(over: Partial<MCPAccessView> = {}, status: Partial<MCPAccessView["status"]> = {}): MCPAccessView {
  return {
    available: true,
    daemon_relay: true,
    remote_source: "daemon",
    enrolled: true,
    managed: true,
    chain_verified: true,
    coverage_rows: [],
    vservers: [],
    effective_state: { status: "effective", reason: "ok", mode: "enforce", running_version: 3, restart_required: false },
    connect: { connectable_servers: [] },
    ...over,
    status: {
      enabled: true,
      mode: "stdio_wrapper",
      audit_mode: "async",
      table_loaded: true,
      cache_path: "/c",
      point_status: "effective",
      chain_head: 0,
      pending_loss: 0,
      launch_specs: 0,
      remote_forwarding: { wired: false, reason: "not enrolled" },
      coverage: {},
      ...status,
    },
  };
}

test("section state: loading, error wins, unavailable body, disabled, on", () => {
  assert.deepEqual(mcpAccessSectionState(null, true, null), { kind: "loading" });
  assert.deepEqual(mcpAccessSectionState(view(), false, "boom"), { kind: "error", message: "boom" });
  assert.deepEqual(mcpAccessSectionState({ available: false, reason: "no relay here" }, false, null), {
    kind: "unavailable",
    message: "no relay here",
  });
  const off = mcpAccessSectionState(view({ daemon_relay: false }, { enabled: false }), false, null);
  assert.equal(off.kind, "disabled");
  assert.match(off.kind === "disabled" ? off.message : "", /no MCP call on this machine is mediated/);
  assert.equal(mcpAccessSectionState(view(), false, null).kind, "on");
});

test("notes: wrapped leftovers while off, restart needed, no grant, pending loss, restart_required", () => {
  const left = mcpAccessSectionState(
    view({ daemon_relay: false }, { enabled: false, launch_specs: 2, projected_clients: ["cursor", "opencode"] }),
    false,
    null,
  );
  assert.equal(left.kind, "disabled");
  const notes = left.kind === "disabled" ? left.notes : [];
  assert.equal(notes.length, 1);
  assert.match(notes[0], /^2 journaled client MCP entries are still wrapped \(cursor, opencode\)/);
  assert.match(notes[0], /observer mcp unwrap/);

  const on = mcpAccessSectionState(
    view(
      { daemon_relay: false, effective_state: { status: "accepted_inert", reason: "mode_observe", mode: "observe", running_version: 2, restart_required: true } },
      { table_loaded: false, pending_loss: 1, point_status: "ineffective", missing_capabilities: ["table.loaded"] },
    ),
    false,
    null,
  );
  const n = on.kind === "on" ? on.notes : [];
  assert.equal(n.length, 5);
  assert.match(n[0], /started with it off/);
  assert.match(n[1], /^The relay point is ineffective \(missing table.loaded\): MCP calls are observed, not enforced/);
  assert.match(n[2], /No tools.mcp_access grant/);
  assert.match(n[3], /^1 decision record could not be written locally and is pending/);
  assert.match(n[4], /restart the daemon to apply it/);
  // A clean enabled read has no notes.
  const clean = mcpAccessSectionState(view(), false, null);
  assert.deepEqual(clean.kind === "on" ? clean.notes : null, []);
});

test("coverageTier: one case per matrix label, unknown never upgraded", () => {
  const cases: [string, string][] = [
    ["mediated", "governed"],
    ["hook-only", "best-effort"],
    ["best-effort", "best-effort"],
    ["uncovered", "ungoverned"],
    ["planned", "planned"],
    ["something-new", "ungoverned"],
  ];
  for (const [label, tier] of cases) assert.equal(coverageTier(label), tier, label);
});

test("coverageGrid: client lines sorted, transports in matrix order, methods paired per cell", () => {
  const rows = [
    row("zed", "stdio", "governed", "uncovered"),
    row("cursor", "remote-http", "catalogue", "best-effort"),
    row("cursor", "stdio", "governed", "mediated"),
    row("cursor", "stdio", "catalogue", "mediated"),
    row("cursor", "remote-http", "governed", "hook-only"),
  ];
  const grid = coverageGrid(rows);
  assert.deepEqual(grid.map((l) => l.client), ["cursor", "zed"]);
  assert.deepEqual(grid[0].cells.map((c) => c.transport), ["stdio", "remote-http"]);
  assert.equal(cellLabel(grid[0].cells[0]), "mediated");
  assert.equal(cellTier(grid[0].cells[0]), "governed");
  assert.equal(cellLabel(grid[0].cells[1]), "calls: hook-only / lists: best-effort");
  assert.equal(cellTier(grid[0].cells[1]), "best-effort");
  // zed has no remote-http row: the cell exists but is "not assessed", tiered ungoverned.
  assert.equal(cellLabel(grid[1].cells[1]), "not assessed");
  assert.equal(cellTier(grid[1].cells[1]), "ungoverned");
});

test("cellTier takes the WEAKER method: mediated calls + uncovered lists is ungoverned", () => {
  const cell = { transport: "stdio", governed: row("c", "stdio", "governed", "mediated"), catalogue: row("c", "stdio", "catalogue", "uncovered") };
  assert.equal(cellTier(cell), "ungoverned");
});

test("coverageSummaryLine: relay off says nothing is measured; otherwise counts per tier", () => {
  assert.equal(coverageSummaryLine([]), "no coverage is measured (relay off)");
  assert.equal(
    coverageSummaryLine([
      row("a", "stdio", "governed", "mediated"),
      row("a", "stdio", "catalogue", "hook-only"),
      row("a", "remote-http", "governed", "uncovered"),
      row("a", "remote-http", "catalogue", "planned"),
    ]),
    "1 of 4 cells relay-governed, 1 best-effort, 1 ungoverned, 1 planned",
  );
});

test("approved servers: flattened in order, credential defaults to none, distinct server count", () => {
  const vs = [
    { id: "vs-1", slug: "gh", servers: [{ id: "gh", target: "https://gh", credential_mode: "vault_user", pinned: true, per_user_connect: true }] },
    { id: "vs-2", slug: "all", servers: [
      { id: "gh", target: "https://gh", credential_mode: "vault_user", pinned: true, per_user_connect: true },
      { id: "fs", target: "stdio:fs", pinned: false, per_user_connect: false },
    ] },
  ];
  const rows = approvedServerRows(vs);
  assert.deepEqual(rows.map((r) => `${r.vserver}/${r.server}/${r.credential}`), ["vs-1/gh/vault_user", "vs-2/gh/vault_user", "vs-2/fs/none"]);
  assert.equal(approvedServerCount(vs), 2);
});

test("chainLine: empty, unverified read, intact, broken", () => {
  const base = view().status;
  assert.equal(chainLine(base, true).text, "no decision records yet");
  assert.match(chainLine({ ...base, chain_head: 5 }, false).text, /not verified on this read/);
  assert.match(chainLine({ ...base, chain_head: 5 }, true).text, /not verified on this read/);
  // The read's own flag wins: a chain_ok that this read did not produce is not claimed.
  assert.match(chainLine({ ...base, chain_head: 5, chain_ok: true }, false).text, /not verified on this read/);
  assert.deepEqual(chainLine({ ...base, chain_head: 5, chain_ok: true }, true), { text: "5 records, chain intact", tone: "ok" });
  assert.equal(chainLine({ ...base, chain_head: 5, chain_ok: false }, true).tone, "danger");
});

test("remote, effective and relay lines", () => {
  assert.equal(remoteLine(view()), "off - not enrolled");
  assert.equal(
    remoteLine(view({}, { remote_forwarding: { wired: true, credential_id: "cred-1", cred_gen: 2 } })),
    "on (credential cred-1 gen 2)",
  );
  assert.deepEqual(effectiveLine(view().effective_state), { text: "effective, enforcing, grant v3", tone: "ok" });
  assert.deepEqual(
    effectiveLine({ status: "effective", reason: "ok", mode: "observe", running_version: 3, restart_required: false }),
    { text: "effective, observe only (not enforcing), grant v3", tone: "warn" },
  );
  assert.deepEqual(effectiveLine({ status: "none", reason: "no_policy", mode: "off", running_version: 0, restart_required: false }), {
    text: "no grant in force (no policy)",
    tone: "neutral",
  });
  assert.equal(
    effectiveLine({ status: "accepted_inert", reason: "mode_observe", mode: "observe", running_version: 2, restart_required: false }).text,
    "accepted inert (mode observe), observe, grant v2",
  );
  assert.equal(relayLine(view({}, { enabled: false }).status), "off");
  assert.equal(
    relayLine(view({}, { point_status: "ineffective", missing_capabilities: ["projection.applied"] }).status),
    "on (stdio_wrapper, audit async), point ineffective, missing projection.applied",
  );
});

test("safeConnectURL: only absolute http(s) URLs become links", () => {
  const c = (url?: string) => ({ url, connectable_servers: [] });
  assert.equal(safeConnectURL(c("https://org.acme:9443/agent-access/connections")), "https://org.acme:9443/agent-access/connections");
  assert.equal(safeConnectURL(c("http://127.0.0.1:9443/agent-access/connections")), "http://127.0.0.1:9443/agent-access/connections");
  assert.equal(safeConnectURL(c("javascript:alert(1)")), "");
  assert.equal(safeConnectURL(c("/agent-access/connections")), "");
  assert.equal(safeConnectURL(c(undefined)), "");
});

// Fixture-driven: the REAL daemon payloads (generated from
// cmd/observer buildMCPAccessView, shared with the VS Code tests and pinned
// against the Go shape by TestMCPAccessView_FixturesMatchGoShape).
const FIXTURES = join(import.meta.dirname, "..", "..", "..", "vscode", "test", "fixtures", "agentAccess");
function fixture(name: string): MCPAccessResponse {
  return JSON.parse(readFileSync(join(FIXTURES, `${name}.json`), "utf8")) as MCPAccessResponse;
}

test("fixtures: each real payload lands in the right frame with honest wording", () => {
  const on = mcpAccessSectionState(fixture("enabled"), false, null);
  assert.equal(on.kind, "on");
  if (on.kind === "on") {
    assert.deepEqual(on.notes, []);
    const rows = on.view.coverage_rows;
    // The grid never shows more governed cells than the matrix measured.
    const governedRows = rows.filter((r) => r.coverage === "mediated").length;
    assert.equal(governedRows, on.view.status.coverage["mediated"] ?? 0);
    const grid = coverageGrid(rows);
    const governedCells = grid.flatMap((l) => l.cells).filter((c) => cellTier(c) === "governed").length;
    assert.ok(governedCells * 2 <= governedRows, `${governedCells} governed cells from ${governedRows} mediated rows`);
    assert.equal(approvedServerCount(on.view.vservers), 1);
    assert.equal(safeConnectURL(on.view.connect), "https://org.acme:9443/agent-access/connections");
    assert.equal(effectiveLine(on.view.effective_state).tone, "ok");
  }
  const ineff = mcpAccessSectionState(fixture("ineffective"), false, null);
  assert.equal(ineff.kind, "on");
  if (ineff.kind === "on") {
    assert.match(ineff.notes[0], /^The relay point is ineffective \(missing projection.applied\)/);
    assert.equal(effectiveLine(ineff.view.effective_state).tone, "warn");
    // An ineffective point never ACKs "effective" (doc3 §12.7, Lane SURF F1).
    assert.equal(ineff.view.effective_state.status, "accepted_inert");
    assert.equal(coverageTally(ineff.view.coverage_rows).governed, 0);
  }
  const unenrolled = mcpAccessSectionState(fixture("unenrolled"), false, null);
  assert.equal(unenrolled.kind === "on" ? safeConnectURL(unenrolled.view.connect) : "x", "");
  assert.equal(mcpAccessSectionState(fixture("disabled"), false, null).kind, "disabled");
  assert.equal(mcpAccessSectionState(fixture("unavailable"), false, null).kind, "unavailable");
});
