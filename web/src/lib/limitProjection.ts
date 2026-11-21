// limitProjection.ts words the run-out projection of the predictor card
// (GET /api/session/<id>/predict, field `projection`; Go:
// internal/predict/projection.go). The server sends numbers and closed codes;
// every sentence a person reads is written here, so it can be shortened in
// one place. Pure: no fetch, no React.
//
// Money goes through the one display seam (fmtCost), so a node whose org
// chose token usage for developers sees tokens, never dollars, and a figure
// with no token counterpart is left out instead of rendering a dash.

import type { Projection, ProjectionNote } from "./types";
import { cachedDateTimeFormat, dollarsShown, fmtCompact, fmtCost, fmtRelative } from "./format";

const LIMIT_LABEL: Record<string, string> = {
  weekly: "Weekly limit",
  "5h": "5-hour window",
};

const BUDGET_PERIOD: Record<string, string> = {
  session: "per-session",
  daily: "daily",
  weekly: "rolling 7-day",
  monthly: "monthly",
};

/** projectionTitle names one limit window or budget. */
export function projectionTitle(p: Projection): string {
  if (p.kind === "limit") return LIMIT_LABEL[p.key] ?? "Usage limit";
  const who = p.origin === "org" ? "Org" : "Your";
  const period = BUDGET_PERIOD[p.key] ?? p.key;
  const tool = p.subject?.startsWith("tool:") ? ` for ${p.subject.slice(5)}` : "";
  return `${who} ${period} budget${tool}`;
}

/** pct renders a 0..1 share as a whole percent; a sliver reads "<1%". */
export function pct(frac: number | null | undefined): string {
  if (frac == null || !Number.isFinite(frac)) return "";
  const v = frac * 100;
  if (v > 0 && v < 1) return "<1%";
  return `${Math.round(v)}%`;
}

/** fmtWhen renders an instant as "Thu 14:00" within a week, else "Nov 20, 14:00". */
export function fmtWhen(unixSec: number, nowMs: number = Date.now()): string {
  const d = new Date(unixSec * 1000);
  const soon = Math.abs(d.getTime() - nowMs) < 6 * 86_400_000;
  const f = soon
    ? cachedDateTimeFormat("en-US", { weekday: "short", hour: "2-digit", minute: "2-digit", hourCycle: "h23" })
    : cachedDateTimeFormat("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hourCycle: "h23" });
  return f.format(d).replace(",", "");
}

/** relUnix is fmtRelative for a unix-seconds instant. */
export function relUnix(unixSec: number, nowMs: number = Date.now()): string {
  return fmtRelative(new Date(unixSec * 1000).toISOString(), nowMs);
}

/** money renders a dollar figure with its token counterpart through the
 *  display seam; null when there is nothing honest to show. */
export function money(usd: number | null | undefined, tokens?: number | null): string | null {
  if (dollarsShown()) {
    if (usd == null || !Number.isFinite(usd)) return tokens != null ? `${fmtCompact(tokens)} tok` : null;
    return fmtCost(usd, tokens);
  }
  return tokens != null && Number.isFinite(tokens) ? fmtCost(usd ?? null, tokens) : null;
}

/** amount renders a budget figure in the budget's own unit. */
export function amount(p: Projection, v: number | null | undefined): string | null {
  if (v == null) return null;
  return p.unit === "tokens" ? `${fmtCompact(v)} tok` : money(v, null);
}

/** joinParts joins the present parts with a middle dot. */
export function joinParts(...parts: (string | null | undefined | false)[]): string {
  return parts.filter((s): s is string => !!s).join(" · ");
}

export type HeadlineTone = "neutral" | "success" | "warn" | "danger";
export type Headline = { text: string; tone: HeadlineTone; sub?: string };

type HeadlineRule = {
  match: (p: Projection) => boolean;
  render: (p: Projection, nowMs: number) => Headline;
};

const readingAge = (p: Projection, nowMs: number) =>
  p.observed_at_unix != null ? `Last reading ${relUnix(p.observed_at_unix, nowMs)}` : "The last reading";

const usedFrac = (p: Projection) => p.used_frac_est ?? p.used_frac;

// HEADLINE_RULES is walked top-down; the first match words the block.
const HEADLINE_RULES: HeadlineRule[] = [
  {
    match: (p) => !!p.run_out?.exhausted,
    render: (p, now) => ({
      text: p.kind === "limit" ? `${projectionTitle(p)} used up` : `${projectionTitle(p)} used up (${pct(usedFrac(p))})`,
      tone: "danger",
      sub: p.resets_at_unix != null ? `Resets ${fmtWhen(p.resets_at_unix, now)}` : undefined,
    }),
  },
  {
    match: (p) => p.state === "reset",
    render: (p, now) => ({
      text: `${readingAge(p, now)}; that window has reset`,
      tone: "neutral",
      sub: "Route a session through the proxy to refresh it.",
    }),
  },
  {
    match: (p) => p.state === "reset_inferred",
    render: (p, now) => ({
      text: `${readingAge(p, now)}; that window has reset`,
      tone: "neutral",
      sub: joinParts(
        "Route a session through the proxy to refresh it",
        p.window_start_unix != null && p.used.tokens > 0
          ? `this machine used ${joinParts(`${fmtCompact(p.used.tokens)} tok`, dollarsShown() ? money(p.used.cost_usd) : null)} since the window likely restarted ${relUnix(p.window_start_unix, now)}`
          : null,
      ) + ".",
    }),
  },
  {
    match: (p) => p.state === "no_reset_time",
    render: (p) => ({ text: `${pct(usedFrac(p))} used; the reading has no reset time`, tone: "neutral" }),
  },
  {
    match: (p) => p.state === "session",
    render: (p) => {
      const left = amount(p, Math.max(0, (p.cap ?? 0) - (p.spent ?? 0)));
      return {
        text: `${pct(p.left_frac)} of this session's budget left`,
        tone: (p.left_frac ?? 1) < 0.2 ? "warn" : "neutral",
        sub: left ? `${left} left of ${amount(p, p.cap)}` : undefined,
      };
    },
  },
  {
    match: (p) => p.run_out?.runs_out_at_unix != null,
    render: (p, now) => ({
      text: `${projectionTitle(p)} runs out ${fmtWhen(p.run_out!.runs_out_at_unix!, now)} at this rate`,
      tone: "warn",
      sub: p.resets_at_unix != null ? `Resets ${fmtWhen(p.resets_at_unix, now)}, ${relUnix(p.resets_at_unix, now)}` : undefined,
    }),
  },
  {
    match: (p) => !!p.run_out?.lasts_until_reset,
    render: (p, now) => ({
      text: `${p.kind === "limit" ? "Lasts until reset" : "Lasts the period"}, about ${pct(p.run_out!.projected_left_at_reset_frac)} left`,
      tone: "success",
      sub: p.resets_at_unix != null ? `Resets ${fmtWhen(p.resets_at_unix, now)}, ${relUnix(p.resets_at_unix, now)}` : undefined,
    }),
  },
  {
    match: (p) => p.state === "rolling" && p.used_frac != null,
    render: (p) => ({ text: `${pct(p.used_frac)} of the rolling 7 days used`, tone: (p.used_frac ?? 0) > 0.8 ? "warn" : "neutral" }),
  },
  {
    match: (p) => p.left_frac != null,
    render: (p) => ({ text: `${pct(p.left_frac)} left; not enough data for a rate yet`, tone: "neutral" }),
  },
];

/** projectionHeadline is the one sentence a block leads with. */
export function projectionHeadline(p: Projection, nowMs: number = Date.now()): Headline {
  for (const r of HEADLINE_RULES) if (r.match(p)) return r.render(p, nowMs);
  return { text: "No reading for this window yet", tone: "neutral" };
}

const NOTE_TEXT: Record<ProjectionNote, string> = {
  not_enough_data: "Under an hour into the window, or nothing used yet, so there is no rate.",
  capacity_too_small: "Under 1% used: too little to size the whole limit in tokens or dollars.",
  carried_forward: "The reading is over 10 minutes old, so usage captured since then is added to it (est.).",
  local_only: "Token and dollar sizes assume all use of this limit was captured here; use on other devices or the web means the real limit is larger.",
  reading_stale: "The reading is over 6 hours old.",
  window_reset: "The window this reading measured has reset.",
  window_inferred: "The current window's start is inferred from the weekly cadence.",
  unpriced_usage: "Some captured usage has no price, so dollar figures are a lower bound.",
  timezone_assumed_utc: "The period is shown in UTC; the budget's own timezone can shift it by a few hours.",
  other_machines: "Spend includes your other machines; sessions are counted on this machine only.",
  exhausted: "Used up.",
  no_message_estimate: "No next-message estimate for this session yet, so prompts left are not shown.",
};

/** noteText words one note code. */
export function noteText(n: ProjectionNote): string {
  return NOTE_TEXT[n] ?? "";
}

const SOURCE_SUFFIX: Record<string, string> = {
  statusline: "status line",
  oauth: "account usage",
  web_usage: "account usage",
  appserver: "Codex app",
  proxy: "proxy headers",
  logs: "session log",
};

/** sourceLabel words where a limit reading came from. */
export function sourceLabel(source: string | undefined): string {
  if (!source) return "";
  if (source === "proxy") return "proxy headers";
  if (source === "transcript") return "session log";
  if (source.startsWith("plans:")) {
    const suffix = source.slice(6).split(".").pop() ?? "";
    const s = SOURCE_SUFFIX[suffix];
    return s ? `Plans & limits, ${s}` : "Plans & limits";
  }
  return "";
}

/** paceText words used against elapsed. */
export function paceText(p: Projection): string | null {
  if (!p.pace) return null;
  const pts = Math.round(Math.abs(p.pace.delta) * 100);
  if (p.pace.verdict === "ahead") return `${pts} pts faster than an even spread`;
  if (p.pace.verdict === "behind") return `${pts} pts slower than an even spread`;
  return "on an even spread";
}

/** trendText compares this window's burn with the previous window's. */
export function trendText(p: Projection): string | null {
  const t = p.trend;
  if (!t) return null;
  if (t.prev_tokens <= 0) return p.used.tokens > 0 ? "new: nothing captured in the previous window" : null;
  if (t.rate_change == null) return null;
  const r = t.rate_change;
  if (Math.abs(r) < 0.05) return "about the same rate as the previous window";
  return `${Math.round(Math.abs(r) * 100)}% ${r > 0 ? "faster" : "slower"} than the previous window`;
}

/** mixText lists the token classes over 1% of the window, largest first. */
export function mixText(p: Projection): string | null {
  const m = p.mix;
  if (!m) return null;
  const parts: [string, number][] = [
    ["cache reads", m.cache_read],
    ["input", m.input],
    ["cache writes", m.cache_write],
    ["output", m.output],
    ["reasoning", m.reasoning],
  ];
  const shown = parts.filter(([, v]) => v >= 0.01).sort((a, b) => b[1] - a[1]);
  return shown.length ? shown.map(([k, v]) => `${k} ${pct(v)}`).join(", ") : null;
}

/** baseName shortens a project path to its last segment. */
export function baseName(path: string): string {
  const parts = path.split(/[\\/]/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : path;
}

/** confidenceText words the confidence of a rate. */
export function confidenceText(p: Projection): string | null {
  if (!p.confidence || !p.burn) return null;
  return `${p.confidence}, from ${p.used.turns} turns over ${p.burn.basis_hours}h`;
}

/** promptsText words the prompts left at the predictor's band. */
export function promptsText(p: Projection): string | null {
  const m = p.more_prompts;
  if (!m) return null;
  const n = (v: number) => (v >= 10 ? Math.floor(v).toString() : v.toFixed(1).replace(/\.0$/, ""));
  return `about ${n(m.mid)} (${n(m.low)} to ${n(m.high)})`;
}
