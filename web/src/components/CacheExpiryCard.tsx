import { useApi } from "@/lib/useApi";
import { fmtInt, fmtUSD } from "@/lib/format";
import { HelpInd } from "@/components/HelpInd";
import { Icon, ModelId, ProgressRing } from "@/components/primitives";
import type { CacheStatusResponse, CacheWindowStatus } from "@/lib/types";
import { cacheLifeRatio } from "@/lib/liveSignals";
import { CACHE_EXPIRY } from "@shared/lib/cacheVocab";
import { vocabView } from "@shared/lib/vocabEntry";
import { VocabPill } from "@shared/lib/vocabPill";
import { TONE_COLOR } from "@shared/lib/tone";

// CacheExpiryCard — the cache-expiry warning surface (Part A of
// docs/plans/cache-expiry-warning-and-keepwarm-plan-2026-06-25.md). Reads
// /api/cache/status and lists the live prompt caches with a live countdown
// to expiry, the dollars at risk if each goes cold, and — when keep-warm
// is in advise/enforce mode — the cheapest content-free lever to keep it
// warm.
//
// Shows warm caches too (with their countdown) so an active session has a
// visible "expires in 3:12" timer, not just at-risk ones. Long-dead cold
// caches are dropped at the boundary; only recently-cold ones surface.
// Hidden entirely when no caches are live. Optional sessionId scopes it to
// one session (used by the SessionDetailPanel).
export function CacheExpiryCard({ sessionId }: { sessionId?: string }) {
  const status = useApi<CacheStatusResponse>(
    "/api/cache/status",
    sessionId ? { session: sessionId } : {},
    [sessionId ?? ""],
    { refreshMs: 5000 },
  );

  const data = status.data;
  if (!data || !data.enabled) return null;

  const windows = data.windows ?? [];
  if (windows.length === 0) return null;

  const atRisk = windows.filter((w) => w.severity !== "ok").length;
  const warm = windows.length - atRisk;
  const showAdvice = data.keepwarm_mode !== "off";

  return (
    <div className="rounded-3 border border-fg-2/12 bg-bg-2/40 px-4 py-3">
      <div className="mb-2 flex items-center justify-between gap-2">
        <span className="flex items-center gap-1.5 text-[12px] font-semibold text-fg-1">
          Cache expiry
          <HelpInd id="card.cache_expiry" />
        </span>
        <span className="text-[10px] uppercase tracking-wide text-fg-3">
          {atRisk > 0 && <span className="text-warn">{atRisk} at risk</span>}
          {atRisk > 0 && warm > 0 && " · "}
          {warm > 0 && <span>{warm} warm</span>}
          {" · keep-warm: "}
          {data.keepwarm_mode}
        </span>
      </div>
      <div className="space-y-1">
        {windows.slice(0, 12).map((w, i) => (
          <CacheExpiryRow key={`${w.window.scope}-${i}`} w={w} showAdvice={showAdvice} />
        ))}
      </div>
    </div>
  );
}

function CacheExpiryRow({
  w,
  showAdvice,
}: {
  w: CacheWindowStatus;
  showAdvice: boolean;
}) {
  const adviceShown = showAdvice && w.recommendation.action !== "none";
  return (
    <div className="rounded-2 px-2 py-1 hover:bg-fg-2/5">
      <div className="flex items-center gap-2 text-[11px]">
        <CacheLifeRing w={w} />
        <span className="w-20 shrink-0 font-mono tabular-nums text-fg-1">
          {timeLabel(w)}
        </span>
        <VocabPill vocab="cacheExpiry" table={CACHE_EXPIRY} value={w.severity} className="shrink-0" />
        <span className="flex min-w-0 flex-1">
          <ModelId model={w.window.model} mono={false} className="min-w-0" />
        </span>
        <span className="shrink-0 text-fg-3">{fmtInt(w.window.prefix_tokens)} tok</span>
        <span
          className={`shrink-0 font-medium ${
            w.severity === "ok" ? "text-fg-2" : "text-warn"
          }`}
        >
          {fmtUSD(w.value_at_risk_usd)}
        </span>
      </div>
      {adviceShown && (
        <div className="mt-0.5 pl-[7.25rem] text-[10px] text-info">
          💡 {w.recommendation.rationale}
        </div>
      )}
    </div>
  );
}

// CacheLifeRing - the countdown as a ring: the share of the window's life
// left, with tone and glyph escalating ok -> soon -> critical -> cold
// (Flame -> Timer -> AlarmClock -> Snowflake) from the ONE CACHE_EXPIRY
// table + VOCAB_ICONS.cacheExpiry. The ratio is measured at the server's
// clock (expires_at minus seconds_to_expiry), the same basis as the text
// countdown beside it. When the window's span is unknown the glyph renders
// alone: no ring, rather than an invented fill.
function CacheLifeRing({ w }: { w: CacheWindowStatus }) {
  const v = vocabView("cacheExpiry", CACHE_EXPIRY, w.severity);
  const serverNow = Date.parse(w.window.expires_at) - w.seconds_to_expiry * 1000;
  const ratio = cacheLifeRatio(w.window, serverNow);
  const glyph = <Icon icon={v.icon} size={10} style={{ color: TONE_COLOR[v.tone] }} />;
  if (ratio == null) {
    return <span className="inline-grid size-5 shrink-0 place-items-center">{glyph}</span>;
  }
  return (
    <ProgressRing ratio={ratio} tone={v.tone} size={20} stroke={2.5} label={`Cache life left (${v.label})`}>
      {glyph}
    </ProgressRing>
  );
}

// timeLabel renders the countdown / relative-expiry for a window. Warm and
// soon/critical show a live countdown ("3:12"); cold shows how long ago it
// expired ("2m ago"). A leading "~" marks an estimated (non-authoritative)
// expiry.
function timeLabel(w: CacheWindowStatus): string {
  const secs = w.seconds_to_expiry;
  const prefix = w.estimated ? "~" : "";
  if (w.severity === "cold" || secs <= 0) {
    return `${ago(-secs)} ago`;
  }
  return `${prefix}${clock(secs)}`;
}

function clock(secs: number): string {
  if (secs >= 60) {
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return `${m}:${s.toString().padStart(2, "0")}`;
  }
  return `${secs}s`;
}

function ago(secs: number): string {
  if (secs >= 60) return `${Math.floor(secs / 60)}m`;
  return `${secs}s`;
}
