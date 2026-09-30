// mcpAccess.ts - the PURE half of the node Security page's "MCP access"
// section (Agent Access P10, doc3 §15 "node dashboard", §12.7 coverage
// honesty, §12.8 effective state).
//
// The section renders GET /api/mcp-access/status, which the daemon composes
// from the SAME derivation `observer mcp status --json` prints
// (cmd/observer/mcp_access_dashboard.go): `status` IS that body, plus the
// coverage matrix rows it summarises, the approved registry, the
// node-mcp-relay effective-state row and the org connect target.
//
// Honesty rules this file makes structural:
//   - coverage is only ever the matrix's own label per client x transport x
//     method; the section groups those labels into governed (relay-mediated)
//     / best-effort / ungoverned / planned and never upgrades a cell;
//   - a disabled relay says nothing is mediated, and still surfaces client
//     configs left wrapped by a relay switched off without `unwrap`;
//   - the record chain is "not verified" unless this read walked it;
//   - remote forwarding is what the daemon's relay runtime resolved at
//     start, with its reason when off - never a guess.
//
// No React, no fetch, no imports: web/src/lib/mcpAccess.test.ts imports it
// directly (node --experimental-strip-types).

/** One coverage matrix cell (coverage.Row on the wire). */
export interface MCPAccessCoverageRow {
  client: string;
  transport: string;
  method: string;
  coverage: string;
  point?: string;
  phase?: string;
  note: string;
}

/** Remote forwarding as the relay runtime resolved it. */
export interface MCPRelayRemote {
  wired: boolean;
  reason?: string;
  credential_id?: string;
  cred_gen?: number;
  machine_fp?: string;
  registered_at?: string;
  issuer?: string;
  gateway_url?: string;
}

/** The `observer mcp status --json` body (mcpRelayStatus). */
export interface MCPRelayStatus {
  enabled: boolean;
  mode: string;
  audit_mode: string;
  listen?: string;
  gateway_url?: string;
  table_loaded: boolean;
  table_version?: number;
  table_mode?: string;
  table_rows?: number;
  policy_gen?: number;
  cache_path: string;
  effective_hash?: string;
  point_status: string;
  missing_capabilities?: string[];
  approved_vservers?: string[];
  chain_head: number;
  chain_ok?: boolean;
  pending_loss: number;
  launch_specs: number;
  projected_clients?: string[];
  remote_forwarding: MCPRelayRemote;
  coverage: Record<string, number>;
}

/** One server inside an approved vserver. */
export interface MCPAccessServer {
  id: string;
  target: string;
  credential_mode?: string;
  pinned: boolean;
  per_user_connect: boolean;
}

/** One approved virtual server. */
export interface MCPAccessVServer {
  id: string;
  slug: string;
  sender_constraint?: string;
  servers: MCPAccessServer[];
}

/** The node-mcp-relay effective-state row (enum-only). */
export interface MCPAccessEffective {
  status: string;
  reason: string;
  mode: string;
  running_version: number;
  effective_hash?: string;
  restart_required: boolean;
}

/** One per-user connect target the accepted grant names. */
export interface MCPConnectableServer {
  server_id: string;
  vservers: string[];
}

/** The org-dashboard connect target; url empty when unavailable says why. */
export interface MCPAccessConnect {
  url?: string;
  dashboard_origin?: string;
  origin_source?: string;
  unavailable?: string;
  connectable_servers: MCPConnectableServer[];
}

/** GET /api/mcp-access/status when the daemon serves it. */
export interface MCPAccessView {
  available: true;
  status: MCPRelayStatus;
  daemon_relay: boolean;
  remote_source: string;
  enrolled: boolean;
  managed: boolean;
  chain_verified: boolean;
  coverage_rows: MCPAccessCoverageRow[];
  vservers: MCPAccessVServer[];
  effective_state: MCPAccessEffective;
  connect: MCPAccessConnect;
}

/** GET /api/mcp-access/status from a process with no relay seam. */
export interface MCPAccessUnavailable {
  available: false;
  reason: string;
}

export type MCPAccessResponse = MCPAccessView | MCPAccessUnavailable;

/** What the section shows before any detail. */
export type MCPAccessSectionState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "unavailable"; message: string }
  | { kind: "disabled"; message: string; notes: string[] }
  | { kind: "on"; view: MCPAccessView; notes: string[] };

const DISABLED_MESSAGE =
  "The node MCP relay is off ([mcp_relay].enabled = false): no MCP call on this machine is mediated, " +
  "and no org grant is enforced here. Turn it on with `observer mcp-relay enable`.";

/** mcpAccessSectionState is the frame the section renders. */
export function mcpAccessSectionState(
  data: MCPAccessResponse | null,
  loading: boolean,
  error: string | null,
): MCPAccessSectionState {
  if (error) return { kind: "error", message: error };
  if (!data) return loading ? { kind: "loading" } : { kind: "unavailable", message: "No MCP access status was returned." };
  if (data.available === false) return { kind: "unavailable", message: data.reason };
  const notes = mcpAccessNotes(data);
  if (!data.status.enabled) return { kind: "disabled", message: DISABLED_MESSAGE, notes };
  return { kind: "on", view: data, notes };
}

/** mcpAccessNotes are the operator-facing caveats, in a fixed order. */
export function mcpAccessNotes(v: MCPAccessView): string[] {
  const notes: string[] = [];
  const s = v.status;
  if (!s.enabled && s.launch_specs > 0) {
    const who = (s.projected_clients ?? []).join(", ");
    notes.push(
      `${s.launch_specs} journaled client MCP entr${s.launch_specs === 1 ? "y is" : "ies are"} still wrapped` +
        (who ? ` (${who})` : "") +
        ": while the relay is off those servers refuse to start. Run `observer mcp unwrap` to restore the originals.",
    );
  }
  if (s.enabled && !v.daemon_relay) {
    notes.push(
      "The relay is on in config but this daemon was started with it off: restart the daemon to bind it (route OFF -> stop -> relaunch -> route ON).",
    );
  }
  if (!s.enabled && v.daemon_relay) {
    notes.push("The relay is off in config but this daemon still runs it until the next restart.");
  }
  if (s.enabled && s.point_status !== "effective") {
    const missing = (s.missing_capabilities ?? []).join(", ");
    notes.push(
      `The relay point is ${s.point_status}${missing ? ` (missing ${missing})` : ""}: MCP calls are observed, not enforced, until it is effective.`,
    );
  }
  if (s.enabled && !s.table_loaded) {
    notes.push("No tools.mcp_access grant has been accepted on this node yet, so there is nothing to enforce.");
  }
  if (s.pending_loss > 0) {
    notes.push(
      `${s.pending_loss} decision record${s.pending_loss === 1 ? "" : "s"} could not be written locally and ${s.pending_loss === 1 ? "is" : "are"} pending as a recorded gap.`,
    );
  }
  if (v.effective_state.restart_required) {
    notes.push("A newer grant version is cached than the one running: restart the daemon to apply it.");
  }
  return notes;
}

/** Coverage tiers the section groups the matrix labels into. */
export type CoverageTier = "governed" | "best-effort" | "ungoverned" | "planned";

/** coverageTier maps one matrix label to its tier; unknown labels are ungoverned (never upgraded). */
export function coverageTier(coverage: string): CoverageTier {
  switch (coverage) {
    case "mediated":
      return "governed";
    case "hook-only":
    case "best-effort":
      return "best-effort";
    case "planned":
      return "planned";
    default:
      return "ungoverned";
  }
}

/** The tier's pill variant (Pill primitive vocabulary). */
export function coverageTierVariant(tier: CoverageTier): "success" | "warn" | "danger" | "neutral" {
  switch (tier) {
    case "governed":
      return "success";
    case "best-effort":
      return "warn";
    case "ungoverned":
      return "danger";
    default:
      return "neutral";
  }
}

/** One client x transport cell: the governed-method and catalogue rows. */
export interface CoverageCell {
  transport: string;
  governed?: MCPAccessCoverageRow;
  catalogue?: MCPAccessCoverageRow;
}

/** One client line of the grid. */
export interface CoverageClientLine {
  client: string;
  cells: CoverageCell[];
}

/** coverageTransports is the ordered transport set present in the rows. */
export function coverageTransports(rows: MCPAccessCoverageRow[]): string[] {
  const order = ["stdio", "remote-http", "hosted-connector"];
  const seen = new Set(rows.map((r) => r.transport));
  const known = order.filter((t) => seen.has(t));
  const extra = [...seen].filter((t) => !order.includes(t)).sort();
  return [...known, ...extra];
}

/** coverageGrid folds the matrix into client lines, one cell per transport. */
export function coverageGrid(rows: MCPAccessCoverageRow[]): CoverageClientLine[] {
  const transports = coverageTransports(rows);
  const byClient = new Map<string, Map<string, CoverageCell>>();
  for (const r of rows) {
    let cells = byClient.get(r.client);
    if (!cells) {
      cells = new Map();
      byClient.set(r.client, cells);
    }
    const cell = cells.get(r.transport) ?? { transport: r.transport };
    if (r.method === "catalogue") cell.catalogue = r;
    else cell.governed = r;
    cells.set(r.transport, cell);
  }
  return [...byClient.keys()].sort().map((client) => ({
    client,
    cells: transports.map((t) => byClient.get(client)?.get(t) ?? { transport: t }),
  }));
}

/** cellLabel words one cell: one label when both methods agree, else both. */
export function cellLabel(cell: CoverageCell): string {
  const g = cell.governed?.coverage;
  const c = cell.catalogue?.coverage;
  if (!g && !c) return "not assessed";
  if (g === c || !c) return g ?? "not assessed";
  if (!g) return c;
  return `calls: ${g} / lists: ${c}`;
}

/** cellTier is the WEAKER of the cell's two tiers (a cell is only as governed as its worst method). */
export function cellTier(cell: CoverageCell): CoverageTier {
  const rank: Record<CoverageTier, number> = { ungoverned: 0, planned: 1, "best-effort": 2, governed: 3 };
  const tiers = [cell.governed, cell.catalogue].filter((r): r is MCPAccessCoverageRow => !!r).map((r) => coverageTier(r.coverage));
  if (tiers.length === 0) return "ungoverned";
  return tiers.reduce((a, b) => (rank[b] < rank[a] ? b : a));
}

/** cellNote joins the distinct row notes of a cell (tooltip copy). */
export function cellNote(cell: CoverageCell): string {
  const notes = [cell.governed, cell.catalogue]
    .filter((r): r is MCPAccessCoverageRow => !!r)
    .map((r) => (r.phase ? `${r.note} (planned: ${r.phase})` : r.note));
  return [...new Set(notes)].join(" | ");
}

/** coverageTally counts matrix rows per tier. */
export function coverageTally(rows: MCPAccessCoverageRow[]): Record<CoverageTier, number> {
  const out: Record<CoverageTier, number> = { governed: 0, "best-effort": 0, ungoverned: 0, planned: 0 };
  for (const r of rows) out[coverageTier(r.coverage)]++;
  return out;
}

/** coverageSummaryLine is the one-line matrix summary. */
export function coverageSummaryLine(rows: MCPAccessCoverageRow[]): string {
  if (rows.length === 0) return "no coverage is measured (relay off)";
  const t = coverageTally(rows);
  return `${t.governed} of ${rows.length} cells relay-governed, ${t["best-effort"]} best-effort, ${t.ungoverned} ungoverned` +
    (t.planned > 0 ? `, ${t.planned} planned` : "");
}

/** One flattened approved-server row. */
export interface ApprovedServerRow {
  vserver: string;
  slug: string;
  server: string;
  target: string;
  credential: string;
  pinned: boolean;
  perUser: boolean;
}

/** approvedServerRows flattens the registry, vserver then server order kept. */
export function approvedServerRows(vservers: MCPAccessVServer[]): ApprovedServerRow[] {
  const out: ApprovedServerRow[] = [];
  for (const v of vservers) {
    for (const s of v.servers) {
      out.push({
        vserver: v.id,
        slug: v.slug,
        server: s.id,
        target: s.target,
        credential: s.credential_mode || "none",
        pinned: s.pinned,
        perUser: s.per_user_connect,
      });
    }
  }
  return out;
}

/** approvedServerCount counts distinct server ids across vservers. */
export function approvedServerCount(vservers: MCPAccessVServer[]): number {
  return new Set(vservers.flatMap((v) => v.servers.map((s) => s.id))).size;
}

/** chainLine words the decision-record chain state. */
export function chainLine(s: MCPRelayStatus, verified: boolean): { text: string; tone: "ok" | "warn" | "danger" | "neutral" } {
  if (s.chain_head === 0) return { text: "no decision records yet", tone: "neutral" };
  if (!verified || s.chain_ok === undefined) {
    return { text: `${s.chain_head} records, not verified on this read (observer mcp doctor verifies it)`, tone: "neutral" };
  }
  if (s.chain_ok) return { text: `${s.chain_head} records, chain intact`, tone: "ok" };
  return { text: `${s.chain_head} records, chain BROKEN - run observer mcp doctor`, tone: "danger" };
}

/** remoteLine words remote forwarding with its source. */
export function remoteLine(v: MCPAccessView): string {
  const r = v.status.remote_forwarding;
  if (r.wired) {
    return `on (credential ${r.credential_id ?? "?"}${r.cred_gen ? ` gen ${r.cred_gen}` : ""})`;
  }
  return `off - ${r.reason || "no reason reported"}`;
}

/** effectiveLine words the effective-state row. */
export function effectiveLine(e: MCPAccessEffective): { text: string; tone: "ok" | "warn" | "neutral" } {
  const reason = e.reason && e.reason !== "ok" ? ` (${e.reason.replace(/_/g, " ")})` : "";
  const version = e.running_version > 0 ? `, grant v${e.running_version}` : "";
  switch (e.status) {
    case "effective":
      // Effective in observe mode records but never blocks: not "ok".
      return e.mode === "enforce"
        ? { text: `effective, enforcing${version}`, tone: "ok" }
        : { text: `effective, ${e.mode} only (not enforcing)${version}`, tone: "warn" };
    case "none":
      return { text: `no grant in force${reason}`, tone: "neutral" };
    default:
      return { text: `${e.status.replace(/_/g, " ")}${reason}, ${e.mode}${version}`, tone: "warn" };
  }
}

/** relayLine words the relay itself (mode, audit, point status). */
export function relayLine(s: MCPRelayStatus): string {
  if (!s.enabled) return "off";
  const missing = (s.missing_capabilities ?? []).length > 0 ? `, missing ${(s.missing_capabilities ?? []).join(", ")}` : "";
  return `on (${s.mode}, audit ${s.audit_mode}), point ${s.point_status}${missing}`;
}

/**
 * safeConnectURL returns the connect URL only when it is an absolute
 * http(s) URL (the daemon builds it from the enrolment origin; this is the
 * defence in depth before it becomes an href). Anything else is "".
 */
export function safeConnectURL(c: MCPAccessConnect): string {
  const raw = (c.url ?? "").trim();
  if (!/^https?:\/\/[^/\s]+/i.test(raw)) return "";
  return raw;
}
