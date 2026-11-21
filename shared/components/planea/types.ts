// The row shapes the Plane A components draw (B5-0, 2026-11-19).
//
// Each is the structural subset a component reads, so the org dashboard's
// rollup rows (web2/src/lib/api.ts ObsTraceListRow, ObsSpanDetail, ...) and
// the node's /api/obs/* rows both satisfy it without an adapter. A field the
// node store does not have is optional here.

/** Content-free eval chip: name, label, score; the rationale stays behind an
 *  audited viewer on the org. */
export interface PlaneAEvalChip {
  name: string;
  label: string;
  score: number;
  explanation?: string;
  span_id?: string;
}

/** Why an end user is empty: the source withheld it, or none was named. */
export type EndUserState = "present" | "none" | "not_shared" | "unknown";

/** The hosted app's identity on a trace or session row (otelident). */
export interface PlaneATraceIdentity {
  end_user?: string;
  end_user_hash?: string;
  end_user_state?: EndUserState;
  tenant?: string;
  service?: string;
  environment?: string;
  release?: string;
  tags?: string[];
  metadata?: Record<string, string>;
}

/** The proxy-exact wedge on a span (joined from api_turns by request id). */
export interface PlaneAProxyEnrichment {
  found: boolean;
  provider: string;
  model: string;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_creation_tokens: number;
  cost_usd: number;
}

/** One span as the inspector draws it. */
export interface PlaneASpan {
  span_id: string;
  parent_span_id: string;
  kind: string;
  name: string;
  started_at: string;
  ended_at: string;
  duration_ms: number;
  status: string;
  model: string;
  provider: string;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  total_tokens: number;
  /** The span's cost; null when nothing priced it (a tool or agent span
   *  with no model call reads a dash, an unpriced call "Unpriced"). */
  cost_usd: number | null;
  cost_source: string;
  request_id: string;
  enrichment?: PlaneAProxyEnrichment;
  /** Every kept number (W4-2, contracts/cost-source.md section 3): the
   *  org's JSON text or the machine's object. */
  cost_detail?: unknown;
  /** Exact minus reported; null/absent unless the source is exact. */
  cost_delta_usd?: number | null;
  gateway_request_id?: string;
}

/** The trace header line's fields. `email` (who pushed it) exists only on
 *  the org. */
export interface PlaneATraceHeader {
  status: string;
  duration_ms: number;
  /** The trace total, paired with cost_provenance (the server computes the
   *  two together); null when no span of it is priced. */
  cost_usd: number | null;
  total_tokens: number;
  started_at: string;
  source: string;
  email?: string;
  session_id?: string;
  /** Where the trace's cost came from (W4-2, contracts/cost-source.md
   *  section 5); absent from a server that predates it. */
  cost_provenance?: PlaneACostProvenance | null;
}

/** A trace's cost provenance (costSource.ts CostProvenance). */
export interface PlaneACostProvenance {
  label: string;
  complete: boolean;
  sources: Record<string, number>;
}

/** One captured content body (prompt, response, tool I/O). */
export interface PlaneAContentEntry {
  span_id: string;
  kind: string;
  content_hash: string;
  content: string;
  has_raw: boolean;
  timestamp: string;
}
