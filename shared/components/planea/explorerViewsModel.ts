// Pure model of the Plane A explorer's saved views and live tail (W5-4,
// lane C9): the shapes both apps send and receive and the buffer and poll
// rules, kept free of React so node's test runner can load it
// (web2/src/lib/planeaC9.test.ts). savedViews.tsx and liveTail.tsx render
// them.

export type PlaneAViewScope = "private" | "team" | "org";

export interface PlaneASavedView {
  id: string;
  name: string;
  page: "traces" | "groups";
  filters: Record<string, string>;
  group_by: string;
  columns: string[];
  scope: PlaneAViewScope;
  team_id?: string;
  owner?: string;
  mine: boolean;
  /** Content-gated values (end user, tag, metadata, content search) were
   *  removed for a viewer without read:content. */
  redacted?: boolean;
  created_at?: string;
  updated_at?: string;
}

/** The body an app POSTs (or PUTs) for a view. */
export interface PlaneAViewDraft {
  name: string;
  page: "traces" | "groups";
  filters: Record<string, string>;
  group_by: string;
  columns: string[];
  scope: PlaneAViewScope;
  team_id?: string;
}

/** viewDraft builds a draft from the page's current state, dropping empty
 *  filters (the server drops them too). */
export function viewDraft(
  name: string,
  page: "traces" | "groups",
  filters: Record<string, string>,
  groupBy: string,
  columns: string[],
  scope: PlaneAViewScope = "private",
  teamId = "",
): PlaneAViewDraft {
  const f: Record<string, string> = {};
  for (const [k, v] of Object.entries(filters)) {
    const t = (v ?? "").trim();
    if (t) f[k] = t;
  }
  const d: PlaneAViewDraft = { name: name.trim(), page, filters: f, group_by: groupBy, columns, scope };
  if (scope === "team" && teamId) d.team_id = teamId;
  return d;
}

/** One tailed trace: the fields both sides send. */
export interface PlaneATailRow {
  trace_id: string;
  root_name?: string;
  status?: string;
  started_at?: string;
  duration_ms?: number;
  cost_usd?: number;
  total_tokens?: number;
  error_count?: number;
  model?: string;
  provider?: string;
  service?: string;
  environment?: string;
  release?: string;
  /** When it arrived: the org's ingest stamp (arrived_at) or the machine's
   *  arrival sequence (seq). */
  arrived_at?: string;
  seq?: number;
}

/** One page of the tail, as both sides answer it. */
export interface PlaneATailPage<R extends PlaneATailRow = PlaneATailRow> {
  cursor: string;
  traces: R[];
  more: boolean;
  poll_interval_ms: number;
  buffer_limit: number;
}

/** mergeTail puts a page's rows (oldest first) on top of the buffer, newest
 *  first, replacing a trace already shown (an org trace that received more
 *  spans arrives again), and keeps at most limit rows. */
export function mergeTail<R extends PlaneATailRow>(buffer: R[], incoming: R[], limit: number): R[] {
  if (incoming.length === 0) return buffer;
  const fresh = new Map<string, R>();
  for (const r of incoming) fresh.set(r.trace_id, r);
  const head = [...fresh.values()].reverse();
  const rest = buffer.filter((r) => !fresh.has(r.trace_id));
  return [...head, ...rest].slice(0, Math.max(1, limit));
}

/** nextPollDelay is how long a polling page waits: at once when more rows
 *  are waiting, the server's interval otherwise, and the Retry-After when it
 *  was told to slow down. */
export function nextPollDelay(page: Pick<PlaneATailPage, "more" | "poll_interval_ms"> | null, retryAfterSeconds?: number): number {
  if (retryAfterSeconds && retryAfterSeconds > 0) return retryAfterSeconds * 1000;
  if (!page) return 3000;
  if (page.more) return 250;
  return Math.max(1000, page.poll_interval_ms || 3000);
}

