// speed.ts - the ONE client-side owner of the Messages "Tok/s" figure
// (S10-SPEED, 2026-09-23). The number itself is computed server-side by
// internal/sessionmsg (Speed / Rate / TimingWire) - the SAME projection on
// the node and the org - and this module only divides the two figures the
// server already vetted and renders the labels. It never divides `output`
// by a timestamp gap: that was the bug (a message's output over the gap to
// the NEXT timeline row showed 500-37,000 tok/s).
//
// What the figure is: END-TO-END OUTPUT THROUGHPUT - generated tokens of the
// row's timed model calls over those calls' captured durations, time to
// first token included. Never a decode speed.

// TpsBasis names where a row's duration came from, strongest first.
export type TpsBasis = "measured" | "native" | "transcript";

// TpsSuppressed names why a row that generated tokens shows no rate.
export type TpsSuppressed = "not_measured" | "too_few_tokens" | "too_short" | "implausible";

// SpeedFields is the wire subset this module reads (sessionmsg.TimingWire).
export type SpeedFields = {
  tps_tokens?: number;
  tps_ms?: number;
  tps_basis?: TpsBasis;
  tps_timed_calls?: number;
  tps_calls?: number;
  tps_suppressed?: TpsSuppressed;
};

// tokensPerSec returns the row's throughput, or null when the server
// suppressed it, when it is missing (an older server that predates the
// tps_tokens field), or when either figure is non-positive.
export function tokensPerSec(m: SpeedFields): number | null {
  if (m.tps_suppressed) return null;
  if (m.tps_tokens == null || m.tps_ms == null) return null;
  if (m.tps_tokens <= 0 || m.tps_ms <= 0) return null;
  return m.tps_tokens / (m.tps_ms / 1000);
}

// fmtTps keeps one decimal under 10 tok/s (where precision matters) and
// rounds to a whole number above it, suffixed "/s".
export function fmtTps(tps: number): string {
  return `${tps >= 10 ? Math.round(tps).toString() : tps.toFixed(1)}/s`;
}

// BASIS is the label table, one row per basis. `short` is the cockpit pill,
// `long` the tooltip wording.
const BASIS: Record<TpsBasis, { short: string; long: string }> = {
  measured: { short: "measured", long: "request duration measured by the capture (proxy or OTel)" },
  native: { short: "native", long: "per-call duration recorded by the tool itself" },
  transcript: { short: "transcript", long: "request span derived from the transcript (input written to last output block) - a lower bound on throughput: it can include client time before the request was sent" },
};

// tpsBasisLabel describes a basis for a tooltip ("" when absent).
export function tpsBasisLabel(basis?: TpsBasis): string {
  return basis ? (BASIS[basis]?.long ?? basis) : "";
}

// tpsBasisShort is the compact basis pill text ("" when absent).
export function tpsBasisShort(basis?: TpsBasis): string {
  return basis ? (BASIS[basis]?.short ?? basis) : "";
}

// SUPPRESSED is the reason table: why a row shows "-".
const SUPPRESSED: Record<TpsSuppressed, string> = {
  not_measured: "speed not measured - this capture recorded no generation duration for this row",
  too_few_tokens: "too few output tokens for a meaningful rate - time to first token dominates",
  too_short: "captured duration too short to contain a real model call",
  implausible: "rate above 1,000 tok/s end-to-end - most likely a capture or unit error, so it is not shown",
};

// tpsSuppressedLabel explains a suppression reason ("" when none).
export function tpsSuppressedLabel(reason?: TpsSuppressed): string {
  return reason ? (SUPPRESSED[reason] ?? reason) : "";
}

// tpsTooltip is the full Tok/s cell tooltip for a row, whether or not a rate
// is shown.
export function tpsTooltip(m: SpeedFields, fmtInt: (n: number) => string, fmtDuration: (ms: number) => string): string {
  const parts: string[] = [];
  if (m.tps_tokens != null && m.tps_ms != null && m.tps_ms > 0) {
    parts.push(`${fmtInt(m.tps_tokens)} generated tokens over ${fmtDuration(m.tps_ms)} (${tpsBasisLabel(m.tps_basis)})`);
  }
  if (m.tps_calls != null && m.tps_timed_calls != null && m.tps_timed_calls < m.tps_calls) {
    parts.push(`measured over ${m.tps_timed_calls} of ${m.tps_calls} model calls`);
  }
  if (m.tps_suppressed) parts.push(tpsSuppressedLabel(m.tps_suppressed));
  parts.push("End-to-end output throughput: includes time to first token.");
  return parts.join(". ");
}
