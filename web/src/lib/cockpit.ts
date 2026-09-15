// cockpit.ts — typed fetch + pure-helper layer for the per-terminal Session
// Cockpit panel (web/src/components/cockpit/). Modeled on lib/projectPanel.ts:
// a small typed surface over the terminal-scoped endpoints plus the pure
// formatting/aggregation helpers the cockpit sections consume.
//
// The panel resolves a terminal token → a live session (Phase 1), then polls
// per-section vitals for that session (Phase 2). Everything here is either a
// wire type, a pure helper, or a single fetch action; React state lives in the
// components.

import { ApiError, fetchJSON } from "./api";
import type { MessageRow, ProcessNode } from "./types";

// ---------------------------------------------------------------------------
// Phase 1 — terminal → session link resolve.
// GET /api/terminal/session/<token> (wire shape FROZEN):
//   {"run_id","kind","tool","correlated":true,"session_id","confidence":0.95}
// Uncorrelated: correlated:false, session_id:"", confidence:0.
// Errors: {"error":"unknown_token"|"remote_view_disabled"|...} with 404/403.
// ---------------------------------------------------------------------------

export type TerminalSessionLink = {
  run_id: string;
  kind: string; // "launch" | "resume" | …
  tool: string;
  correlated: boolean;
  session_id: string; // "" while uncorrelated
  confidence: number; // 0..1
};

export type TerminalLinkErrorCode =
  | "unknown_token"
  | "remote_view_disabled"
  | "request_failed"
  | string;

export type TerminalLinkErrorInfo = {
  code: TerminalLinkErrorCode;
  status: number;
};

/** The link-resolve endpoint path for a terminal token. */
export function terminalLinkPath(token: string): string {
  return `/api/terminal/session/${encodeURIComponent(token)}`;
}

// parseLinkError distills a useApi fetch error (fetchJSON throws ApiError,
// whose message embeds the `{error}` envelope body) into the typed wire code
// so the panel can pick honest copy. Falls back to a status-derived guess when
// the body wasn't JSON.
export function parseLinkError(err: Error | null): TerminalLinkErrorInfo | null {
  if (!err) return null;
  const status = err instanceof ApiError ? err.status : 0;
  let code: TerminalLinkErrorCode = "request_failed";
  const m = /"error"\s*:\s*"([a-z_]+)"/.exec(err.message);
  if (m) {
    code = m[1];
  } else if (status === 404) {
    code = "unknown_token";
  } else if (status === 403) {
    code = "remote_view_disabled";
  }
  return { code, status };
}

// WEAK_LINK_CONFIDENCE — below this the correlation is NOT authoritative; the
// header shows an "≈ linked" badge so the operator knows the session/terminal
// match isn't a hard token binding. Only the out-of-band 0.95 correlation is
// authoritative — the marker (0.70) and discovered (0.75) heuristics sit below
// 0.9 and are practically weak, so the badge must cover them (a `< 0.7` gate
// missed both).
export const WEAK_LINK_CONFIDENCE = 0.9;

// ---------------------------------------------------------------------------
// Pure time / id / rate helpers.
// ---------------------------------------------------------------------------

/** Whole seconds between `iso` and now (never negative). null on empty/bad. */
export function secondsSince(iso?: string | null, nowMs: number = Date.now()): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return Math.max(0, Math.floor((nowMs - t) / 1000));
}

/** Signed whole seconds from now until `iso` (negative once past). */
export function secondsUntil(iso?: string | null, nowMs: number = Date.now()): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return Math.round((t - nowMs) / 1000);
}

/** Compact elapsed: "45s" · "3m 20s" · "4h 12m". */
// fmtElapsed was promoted into the shared design system (shared/lib/format.ts)
// so the shared session-detail components can render elapsed times; re-exported
// here so existing @/lib/cockpit importers are unchanged.
export { fmtElapsed } from "@shared/lib/format";

/** Short relative age: "4s ago" · "3m ago" · "2h ago" · "5d ago". */
export function fmtAgo(secs: number | null | undefined): string {
  if (secs == null || !Number.isFinite(secs) || secs < 0) return "-";
  if (secs < 60) return `${secs}s ago`;
  const m = Math.floor(secs / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

/** m:ss countdown for a positive seconds value (cache chips). */
export function fmtCountdown(secs: number): string {
  if (secs <= 0) return "0:00";
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return `${m}:${s.toString().padStart(2, "0")}`;
}

/** First `n` chars of an id (the header's session short-id). */
export function shortId(id: string, n = 10): string {
  return id.length > n ? id.slice(0, n) : id;
}

// LIVE_THRESHOLD_SECS — activity within this window ⇒ the "live" status dot.
export const LIVE_THRESHOLD_SECS = 30;

/** Live = most-recent activity within LIVE_THRESHOLD_SECS. */
export function isLive(lastActivityIso?: string | null, nowMs: number = Date.now()): boolean {
  const s = secondsSince(lastActivityIso, nowMs);
  return s != null && s <= LIVE_THRESHOLD_SECS;
}

// tokensPerSec — OUTPUT tokens per second for a turn. Ported verbatim from
// SessionDetailPanel.tokensPerSec: only output tokens count (input/cache
// tokens aren't generated), and tps_ms is the best server-chosen timing
// source (see tps_basis). null when there's no output or no/zero timing.
export function tokensPerSec(m: MessageRow): number | null {
  if (m.output <= 0 || m.tps_ms == null || m.tps_ms <= 0) return null;
  return m.output / (m.tps_ms / 1000);
}

/** One-decimal under 10 tok/s, whole above, "/s" suffixed. */
export function fmtTps(tps: number): string {
  return `${tps >= 10 ? Math.round(tps).toString() : tps.toFixed(1)}/s`;
}

/** Human label for the timing basis behind a tok/s value. */
export function tpsBasisLabel(basis: MessageRow["tps_basis"]): string {
  switch (basis) {
    case "measured":
      return "measured response time (proxy)";
    case "intra-turn":
      return "intra-turn generation span";
    case "elapsed":
      return "elapsed (to next message)";
    default:
      return "estimated";
  }
}

// newestMessage returns the latest MessageRow by timestamp. The tail endpoint
// may hand rows back oldest-first, so we don't assume slice order.
export function newestMessage(rows: MessageRow[]): MessageRow | null {
  let best: MessageRow | null = null;
  for (const m of rows) {
    if (!best || Date.parse(m.timestamp) >= Date.parse(best.timestamp)) best = m;
  }
  return best;
}

// newestAssistantWithOutput returns the latest assistant turn that actually
// generated output — the turn whose tok/s is worth showing in the Now strip.
export function newestAssistantWithOutput(rows: MessageRow[]): MessageRow | null {
  let best: MessageRow | null = null;
  for (const m of rows) {
    if (m.role !== "assistant" || m.output <= 0) continue;
    if (!best || Date.parse(m.timestamp) >= Date.parse(best.timestamp)) best = m;
  }
  return best;
}

export type BurnRate = {
  usdPerHour: number;
  /** How the rate was derived, so the UI can label it instead of implying
   *  a precision it doesn't have. */
  basis: "recent" | "session";
  /** Seconds the rate was measured over. */
  spanSecs: number;
  /** Turns in the numerator (0 for the session-average basis). */
  turns: number;
};

/** Burn rate in USD/hour for a running session — the number that answers
 *  "should I stop this?", which a running total never does.
 *
 *  Preferred basis is the turns the cockpit already polls (a tail, not the
 *  whole session), so the rate reflects what the session is costing NOW
 *  rather than being diluted by earlier idle time. The oldest fetched turn
 *  is the window BOUNDARY, not a sample: its cost was incurred before the
 *  window opened, so it sets the denominator but is excluded from the
 *  numerator. Counting it would inflate the rate by N/(N-1) — ~20% at the
 *  cockpit's tail of six.
 *
 *  Falls back to the session average over the same elapsed value the header
 *  displays, so the two can never disagree. Returns null when neither basis
 *  is available, rather than a confident "$0.00/h" on no evidence — a rate
 *  needs an interval, and that is the failure mode this codebase keeps
 *  fixing. Note the precise claim: null means NO BASIS. A basis that really
 *  measures zero dollars still returns 0, which is an observation, not a
 *  guess — and it agrees with the session total rendered beside it.
 */
export function burnRate(
  rows: MessageRow[],
  costUsd?: number | null,
  elapsedSecs?: number | null,
): BurnRate | null {
  if (rows.length >= 2) {
    const sorted = [...rows].sort(
      (a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp),
    );
    const startMs = Date.parse(sorted[0].timestamp);
    const spanSecs =
      (Date.parse(sorted[sorted.length - 1].timestamp) - startMs) / 1000;
    if (Number.isFinite(spanSecs) && spanSecs > 0) {
      // Exclude EVERY row at the boundary instant, not just index 0. A user
      // turn and the assistant turn answering it routinely share a
      // timestamp, and skipping only the first would count the other's cost
      // against a window it contributed no time to.
      let usd = 0;
      let turns = 0;
      for (const m of sorted) {
        if (Date.parse(m.timestamp) === startMs) continue;
        usd += Number.isFinite(m.cost_usd) ? m.cost_usd : 0;
        turns++;
      }
      // usd > 0, not turns > 0: the backend synthesizes user rows with a
      // zero cost, so a tail like [user $0, assistant $1, user $0] leaves a
      // costless row after boundary exclusion and would report a "recent"
      // $0/h — a basis label claiming we measured current spend when we
      // measured none. Fall through to the session average instead.
      const usdPerHour = usd / (spanSecs / 3600);
      if (usd > 0 && Number.isFinite(usdPerHour)) {
        return { usdPerHour, basis: "recent", spanSecs, turns };
      }
    }
  }
  if (
    costUsd != null &&
    Number.isFinite(costUsd) &&
    costUsd >= 0 &&
    elapsedSecs != null &&
    elapsedSecs > 0
  ) {
    return {
      usdPerHour: costUsd / (elapsedSecs / 3600),
      basis: "session",
      spanSecs: elapsedSecs,
      turns: 0,
    };
  }
  return null;
}

/** A short "what just happened" label for the newest message row. */
export function activityLabel(m: MessageRow): string {
  const calls = m.tool_calls ?? [];
  if (calls.length > 0) {
    const last = calls[calls.length - 1];
    return last.raw_tool_name || last.action_type || m.role;
  }
  return m.role;
}

/** Last path segment of an exe/command (POSIX or Windows separators). */
export function basename(p: string): string {
  if (!p) return "?";
  const parts = p.split(/[\\/]/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : p;
}

// ---------------------------------------------------------------------------
// Process-tree aggregation.
// ---------------------------------------------------------------------------

/** Depth-first flatten of a process forest. */
export function flattenProcs(roots: ProcessNode[] | null | undefined): ProcessNode[] {
  const out: ProcessNode[] = [];
  const walk = (ns: ProcessNode[]) => {
    for (const n of ns) {
      out.push(n);
      walk(n.children ?? []);
    }
  };
  walk(roots ?? []);
  return out;
}

/** Count of still-running (not exited) processes in the forest. */
export function runningProcessCount(roots: ProcessNode[] | null | undefined): number {
  return flattenProcs(roots).filter((n) => !n.exited).length;
}

// ---------------------------------------------------------------------------
// Network traffic — the server-side aggregate from
// GET /api/session/<id>/network?summary=1 (wire shape FROZEN):
//   {"proxied_calls":N,"request_bytes":N,"response_bytes":N,"os_connections":N}
// The server discriminates PROXIED API calls (SuperBased-proxied/plaintext
// flows, which carry body byte totals) from OS-OBSERVED process connections
// (`os_connections` — raw sockets seen on the process tree, NOT proxied API
// calls and with no body bytes). The old event-list summary conflated the two
// and could never show bytes (the list omits bodies) — this replaces it.
// ---------------------------------------------------------------------------

export type SessionNetworkSummary = {
  proxied_calls: number;
  request_bytes: number;
  response_bytes: number;
  os_connections: number;
};

// networkSummary defensively coerces the aggregate to finite non-negative
// numbers (a malformed field never renders as NaN). null in ⇒ zeros, so
// callers distinguish "no traffic" from "fetch failed" via the ApiState error,
// NOT by treating a missing response as an observed zero (Fix D).
export function networkSummary(
  resp: SessionNetworkSummary | null | undefined,
): SessionNetworkSummary {
  const n = (v: unknown): number =>
    typeof v === "number" && Number.isFinite(v) && v > 0 ? v : 0;
  return {
    proxied_calls: n(resp?.proxied_calls),
    request_bytes: n(resp?.request_bytes),
    response_bytes: n(resp?.response_bytes),
    os_connections: n(resp?.os_connections),
  };
}

// ---------------------------------------------------------------------------
// Rate-limit gauge util normalization. Anthropic unified-header util spellings
// are 0–1 in some builds, 0–100 in others (the predict parser is defensive);
// normalize to a 0–100 percentage clamped to range. null when absent.
// ---------------------------------------------------------------------------

export function utilPct(v: number | null | undefined): number | null {
  if (v == null || !Number.isFinite(v)) return null;
  const pct = v <= 1 ? v * 100 : v;
  return Math.max(0, Math.min(100, pct));
}

// ---------------------------------------------------------------------------
// Phase-2 action — enable OS-level process capture.
// POSTs the dedicated, server-side, ATOMIC verb /api/process/enable-capture
// (no request body). The server does the whole decision under its config-write
// lock: it turns [observer.process].enabled on and, if the configured backend
// is one the daemon's selector builds NOTHING for (off / "" / the not-yet-
// implemented etw + endpointsecurity stubs / any unknown value), switches it to
// "auto" and reports switched_backend + previous_backend. A runnable backend
// (poll / bridge / both / linux_ebpf / auto) is preserved. Already-on + runnable
// is an idempotent no-op (no write, restart_required:false).
//
// This replaces the old GET-config → decide → PUT-section dance: there is no
// client-side read-then-write window, and "which backends actually start"
// lives with the selector on the server, not guessed in the browser.
// ---------------------------------------------------------------------------

export type EnableProcessResult = {
  restart_required: boolean;
  // True when the server switched a non-runnable backend (e.g. "off") to
  // automatic selection — the CTA's success notice names this so the operator
  // knows. Mapped from the wire's `switched_backend`.
  switchedToAuto: boolean;
  // The pre-switch backend value, meaningful only when switchedToAuto. Empty
  // string means the config had no backend set; the notice renders that as
  // "unset". Mapped from the wire's `previous_backend`.
  previousBackend: string;
  // True when the host has NO runnable capture backend at all (e.g. macOS:
  // poll stub, no eBPF, no WSL bridge). The server refuses the flip and the CTA
  // shows `unsupportedDetail` instead of a success notice. From `reason`.
  unsupported: boolean;
  // Operator-facing sentence for the unsupported-platform case (server-authored,
  // names the GOOS). From the wire's `detail`.
  unsupportedDetail: string;
};

export async function enableProcessCapture(): Promise<EnableProcessResult> {
  const res = await fetchJSON<{
    enabled: boolean;
    backend?: string;
    switched_backend: boolean;
    previous_backend?: string;
    restart_required: boolean;
    reason?: string;
    detail?: string;
  }>("/api/process/enable-capture", undefined, { method: "POST" });
  return {
    restart_required: res.restart_required,
    switchedToAuto: res.switched_backend,
    previousBackend: res.previous_backend ?? "",
    unsupported: res.reason === "unsupported_platform",
    unsupportedDetail: res.detail ?? "",
  };
}
