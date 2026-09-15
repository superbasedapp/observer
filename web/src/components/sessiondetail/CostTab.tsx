import { useMemo, useState } from "react";
import clsx from "clsx";
import { ComboChip, Pill, type ComboOption } from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { HelpInd } from "@/components/HelpInd";
import { useApi } from "@/lib/useApi";
import { fmtCompact, fmtInt, fmtUSD } from "@/lib/format";
import type {
  CacheForecastResponse,
  CacheForecastWarning,
  PredictBand,
  PredictResponse,
  PredictWarning,
  PricingDefaultsResponse,
  SessionDetail,
} from "@/lib/types";

// Cost & limits tab — "what will this cost me next?".
//
// The three blocks the design proposal listed separately (next-message
// predictor, 5-hour/weekly limit gauge, model-switch forecast) are two
// components in the code: PredictLimitSection already renders INSIDE
// PredictorBody, so the limit gauge has always been part of the predictor
// card. All extracted VERBATIM from SessionDetailPanel.tsx during the tab
// split.
//
// HONEST GATING. ForecastWidget keeps its exact original gate (d.model must be
// non-empty — the forecaster compares a CURRENT model against a candidate, so
// with no recorded current model there is nothing to compare from). When it is
// gated off the tab says so rather than silently rendering one card.
export function CostTab({ d }: { d: SessionDetail }) {
  return (
    <div className="space-y-5">
      <PredictorCard sessionId={d.id} tool={d.tool} />
      {d.model ? (
        <ForecastWidget sessionId={d.id} />
      ) : (
        <p className="rounded-3 border border-dashed border-line-2 px-4 py-3 text-[11.5px] text-fg-3">
          Model-switch forecast unavailable - this session has no recorded
          current model (<span className="font-mono">model</span> is empty on{" "}
          <span className="font-mono">/api/session/{d.id}</span>), and the
          forecast is a comparison against it.
        </p>
      )}
    </div>
  );
}

// PredictorCard — the Next-Message Cost & Limit Predictor. Two composed
// halves: the cost band (always on where the session has token data) and
// the limit gauge (proxy-gated; renders a help-icon "needs proxy" state
// until the proxy captures the provider's rate-limit headers).
// Backed by GET /api/session/<id>/predict (pure read-side math over
// token_usage — no new tables for the estimate half).
function PredictorCard({ sessionId, tool }: { sessionId: string; tool: string }) {
  const predict = useApi<PredictResponse>(
    `/api/session/${sessionId}/predict`,
    undefined,
    [sessionId],
  );

  return (
    <section className="mt-5 rounded-3 border bg-bg-2 px-4 py-3">
      <div className="flex items-center justify-between gap-2">
        <span className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          Next-message cost predictor
          <HelpInd id="glossary.cost_predictor" />
        </span>
      </div>
      <p className="mt-1 text-[10.5px] text-fg-3">
        Estimated cost of your next message on this session's current model -
        a low / typical / high range over the message's likely turn fan-out.
      </p>

      <ChartState
        loading={predict.loading && !predict.data}
        error={predict.error}
        empty={!predict.data}
        emptyHint="Loading estimate…"
        height={80}
      >
        {predict.data && <PredictorBody data={predict.data} tool={tool} />}
      </ChartState>
    </section>
  );
}

function PredictorBody({ data, tool }: { data: PredictResponse; tool: string }) {
  const est = data.estimate;
  return (
    <div className="mt-2 space-y-3">
      {est.has_estimate ? (
        <>
          <div className="grid grid-cols-3 gap-2">
            <PredictBandStat
              label="Low"
              sub="quick reply"
              band={est.low}
              prefixTokens={est.prefix_tokens}
            />
            <PredictBandStat
              label="Typical"
              sub="median message"
              band={est.mid}
              prefixTokens={est.prefix_tokens}
              highlight
            />
            <PredictBandStat
              label="High"
              sub="agentic loop"
              band={est.high}
              prefixTokens={est.prefix_tokens}
            />
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            <PredictTurnsTierPill tier={est.turns_tier} />
            {(est.warnings ?? [])
              .filter((w) => w !== "turns_inferred_prior" && w !== "turns_inferred_default")
              .map((w) => (
                <PredictWarningPill key={w} kind={w} />
              ))}
          </div>
          <div className="text-[10.5px] text-fg-3">
            <span className="font-mono text-fg-2">{est.model}</span> · cached
            prefix {fmtCompact(est.prefix_tokens)} tok re-read - and billed -
            each turn ·{" "}
            {est.turns_tier === "observed"
              ? `${fmtInt(est.sample_messages)} messages observed`
              : "fan-out inferred (no per-message boundaries on this session)"}
          </div>
        </>
      ) : (
        <div className="rounded-3 border border-dashed bg-bg-1 px-3 py-2.5 text-[11px] text-fg-2">
          <span className="font-medium text-fg-1">No cost estimate yet.</span>{" "}
          {data.reason ||
            "This session has no model/token data captured."}{" "}
          {tool === "cursor" ? "Cursor must report usage through its hooks before a token-based estimate is available." : <>Route this client through the observer proxy (<code className="font-mono text-[10.5px] text-fg-2">observer init</code>) so future messages capture token &amp; cost data.</>}
        </div>
      )}

      {/* Limit gauge — proxy-gated half. */}
      <PredictLimitSection limit={data.limit} />
    </div>
  );
}

// fmtPredictUSD keeps the three band headlines decimal-consistent: 2
// decimals normally (so $0.66 sits cleanly next to $3.82), escalating to
// finer precision only for sub-cent amounts that would otherwise round to
// $0.00.
function fmtPredictUSD(n: number): string {
  if (!Number.isFinite(n)) return "-";
  if (n > 0 && n < 0.01) return fmtUSD(n, true);
  return fmtUSD(n);
}

// predictBilledTokens is the token counterpart of the priced formula
// (per_turn = P·r_cache_read + S·r_input + O·r_output; message = T ×
// per_turn). It counts exactly the dimensions the price counts, so the
// tokens and the dollars agree: the cached prefix P is re-read — and
// billed at the cache-read rate — on EVERY one of the T turns, so it is
// counted T times. `fresh` is the genuinely-new half (S + O per turn).
// Cache-WRITE tokens are not modelled by the estimator, so they are not
// counted here either (disclosed in the tooltip + glossary).
function predictBilledTokens(band: PredictBand, prefixTokens: number) {
  const turns = Math.max(0, band.turns);
  const cached = Math.round(turns * Math.max(0, prefixTokens));
  const fresh = Math.round(
    turns * (Math.max(0, band.fresh_input) + Math.max(0, band.output)),
  );
  return { billed: cached + fresh, cached, fresh };
}

function PredictBandStat({
  label,
  sub,
  band,
  prefixTokens,
  highlight,
}: {
  label: string;
  sub: string;
  band: PredictBand;
  prefixTokens: number;
  highlight?: boolean;
}) {
  const tok = predictBilledTokens(band, prefixTokens);
  return (
    <div
      className={clsx(
        "flex flex-col rounded-3 border px-2.5 py-2",
        highlight ? "border-accent bg-accent-soft" : "bg-bg-1",
      )}
    >
      <span className="text-[10px] font-medium uppercase tracking-[0.05em] text-fg-3">
        {label}
      </span>
      <span
        className={clsx(
          "tabular-nums text-[15px] font-semibold leading-tight",
          highlight ? "text-accent" : "text-fg-1",
        )}
      >
        {fmtPredictUSD(band.message_usd)}
      </span>
      <span className="mt-0.5 text-[10px] text-fg-3">
        ~{band.turns} turns · {fmtCompact(band.output)} out/turn
      </span>
      <span
        className="text-[10px] tabular-nums text-fg-3"
        title={
          `Billed tokens = turns × (cached prefix + fresh input + output) = ` +
          `${band.turns} × (${fmtInt(prefixTokens)} + ${fmtInt(band.fresh_input)} + ${fmtInt(band.output)}) ` +
          `≈ ${fmtInt(tok.billed)}. Of that, ${fmtInt(tok.cached)} is the SAME cached prefix ` +
          `re-read (and billed at the cache-read rate) on every turn - only ${fmtInt(tok.fresh)} is new. ` +
          `This is throughput, not context size. Cache-WRITE tokens are not included.`
        }
      >
        <span className="text-fg-2">{fmtCompact(tok.billed)} tok</span> billed ·{" "}
        {fmtCompact(tok.fresh)} new
      </span>
      <span className="text-[10px] text-fg-3">{sub}</span>
    </div>
  );
}

function PredictTurnsTierPill({ tier }: { tier: PredictResponse["estimate"]["turns_tier"] }) {
  if (tier === "observed") {
    return <Pill variant="success">fan-out: observed</Pill>;
  }
  if (tier === "prior") {
    return <Pill variant="info">fan-out: inferred (similar sessions)</Pill>;
  }
  if (tier === "default") {
    return <Pill variant="neutral">fan-out: inferred (default)</Pill>;
  }
  return null;
}

function PredictWarningPill({ kind }: { kind: PredictWarning }) {
  const labels: Partial<Record<PredictWarning, string>> = {
    empty_prefix: "no cache prefix yet",
    fast_mode_active: "model in fast tier (2×)",
    no_session_history: "no history",
    no_pricing: "no pricing for this model",
  };
  const label = labels[kind];
  if (!label) return null;
  const variant: "warn" | "neutral" = kind === "fast_mode_active" ? "warn" : "neutral";
  return <Pill variant={variant}>{label}</Pill>;
}

// PredictLimitSection renders the 5h/weekly limit gauge. Source is either
// the proxy (Anthropic response headers) or the tool's own session log
// (codex token_count rate_limits — "from session log"). When neither is
// available it shows the help-icon "route through the proxy to unlock"
// state (Anthropic) or the "provider exposes no window" note.
function PredictLimitSection({ limit }: { limit: PredictResponse["limit"] }) {
  return (
    <div className="rounded-3 border bg-bg-1 px-3 py-2.5">
      <div className="flex items-center gap-1.5">
        <span className="text-[10.5px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          5-hour / weekly limit
        </span>
        <HelpInd id="glossary.limit_gauge" />
        {limit.needs_proxy && <Pill variant="neutral">needs proxy</Pill>}
        {limit.available && limit.source === "transcript" && (
          <Pill variant="neutral">from session log</Pill>
        )}
        {limit.available && limit.observed_age && (
          <span className="text-[10px] text-fg-3">· {limit.observed_age}</span>
        )}
      </div>
      {limit.available ? (
        <div className="mt-1.5 grid grid-cols-2 gap-3 text-[11px]">
          <LimitWindowStat
            label="5-hour window"
            util={limit.window_5h_util}
            reset={limit.window_5h_reset}
          />
          <LimitWindowStat
            label="Weekly cap"
            util={limit.window_7d_util}
            reset={limit.window_7d_reset}
          />
        </div>
      ) : limit.no_window ? (
        <p className="mt-1 text-[10.5px] text-fg-3">
          This provider doesn't expose a 5-hour / weekly subscription window in
          its response headers, so only the cost estimate above is available.
        </p>
      ) : (
        <p className="mt-1 text-[10.5px] text-fg-3">
          Route this client through the observer proxy (
          <code className="font-mono text-[10.5px] text-fg-2">observer init</code>
          ) to see how much of your 5-hour and weekly subscription window each
          message consumes. These numbers live only in the provider's response
          headers, which the proxy is the only component able to read.
        </p>
      )}
    </div>
  );
}

function LimitWindowStat({
  label,
  util,
  reset,
}: {
  label: string;
  util?: number;
  reset?: number;
}) {
  const pct = util != null ? Math.round(util * 100) : null;
  const remaining = pct != null ? 100 - pct : null;
  return (
    <div className="flex flex-col">
      <span className="text-[10px] font-medium uppercase tracking-[0.05em] text-fg-3">
        {label}
      </span>
      <span className="tabular-nums text-[12.5px] font-semibold text-fg-1">
        {remaining != null ? `${remaining}% left` : "-"}
      </span>
      {reset != null && (
        <span className="mt-0.5 text-[10px] text-fg-3">
          resets {fmtResetClock(reset)}
        </span>
      )}
    </div>
  );
}

// fmtResetClock renders a unix-seconds reset timestamp as a short
// relative countdown ("in 1h52m") falling back to a local time.
function fmtResetClock(unixSec: number): string {
  const ms = unixSec * 1000;
  const delta = ms - Date.now();
  if (delta <= 0) return "now";
  const mins = Math.round(delta / 60000);
  if (mins < 60) return `in ${mins}m`;
  const h = Math.floor(mins / 60);
  const m = mins % 60;
  return `in ${h}h${m > 0 ? `${m}m` : ""}`;
}

// ForecastWidget — operator-facing surface for the model-switch
// cost forecaster. Pick a candidate model from the dropdown
// (populated from the cost engine's baked-in pricing table via
// /api/config/pricing/defaults), fetch /api/session/<id>/cache/
// forecast?model=X, render the headline numbers (switch_cost,
// break_even, savings/turn, net_savings) + the closed-set warning
// list as pills.
//
// The picker is a ComboChip — searchable single-select with
// keyboard nav over ~180 pricing-table entries. Family-grouped
// labels surface the model family ("claude / opus 4.7") so the
// operator doesn't need to memorize the exact 20251001 suffix.
// Right-aligned per-row metadata shows the input rate ($/M) so
// the operator sees the price gradient at a glance during the
// pick (the forecast itself is the source of truth for the
// downstream numbers; this is just an anchor to inform the choice).
function ForecastWidget({ sessionId }: { sessionId: string }) {
  const [candidate, setCandidate] = useState("");
  const [submitted, setSubmitted] = useState<string | null>(null);
  // Pricing defaults — cached at module level via useApi's
  // built-in identity; the dropdown only needs the model id list,
  // not the per-bucket rates (the forecast call re-derives those
  // server-side). We DO surface the input rate as right-aligned
  // metadata so the operator sees cheap vs expensive at a glance
  // during the pick.
  const pricing = useApi<PricingDefaultsResponse>(
    "/api/config/pricing/defaults",
    undefined,
    [],
  );

  const forecast = useApi<CacheForecastResponse>(
    submitted ? `/api/session/${sessionId}/cache/forecast?model=${encodeURIComponent(submitted)}` : null,
    undefined,
    [sessionId, submitted],
  );

  // Build the dropdown options once per pricing fetch. Sort by
  // (family, model id) so the operator sees claude-/gpt-/gemini-/
  // … grouped naturally — ComboChip's flat list + the per-row
  // family prefix in the label reads like an optgroup without
  // needing a separate primitive.
  const options = useMemo<ComboOption[]>(() => {
    if (!pricing.data?.defaults) return [];
    const entries = Object.entries(pricing.data.defaults);
    entries.sort((a, b) => a[0].localeCompare(b[0]));
    return entries.map(([modelId, p]) => {
      const inputRate = p?.input ?? 0;
      const family = familyOf(modelId);
      return {
        value: modelId,
        // Label shows the family as a muted prefix + the bare model
        // id so a scan column-aligns: "claude   opus-4-7-20251001".
        label: (
          <span className="flex w-full items-baseline gap-1.5">
            {family && (
              <span className="text-[10px] uppercase tracking-[0.05em] text-fg-3">
                {family}
              </span>
            )}
            <span className="font-mono">{stripFamilyPrefix(modelId, family)}</span>
          </span>
        ),
        searchable: modelId.toLowerCase(),
        rightMeta: inputRate > 0 ? `$${inputRate}/M` : undefined,
        title: `Input ${inputRate}/M · Output ${p?.output ?? 0}/M · Cache R ${p?.cache_read ?? 0}/M · Cache W ${p?.cache_creation ?? 0}/M`,
      };
    });
  }, [pricing.data]);

  const onForecast = () => {
    if (candidate) setSubmitted(candidate);
  };

  return (
    <section className="mt-5 rounded-3 border bg-bg-2 px-4 py-3">
      <div className="flex items-center justify-between gap-2">
        <span className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          Next-message cost forecast · model switch
          <HelpInd id="glossary.forecaster_math" />
        </span>
      </div>
      <p className="mt-1 text-[10.5px] text-fg-3">
        Per-turn cost of switching this session's model - works for any session
        with token data; observed cache (claude-code/codex) additionally refines
        the one-time switch cost.
      </p>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <label className="text-[11px] text-fg-2">Switch to:</label>
        <ComboChip
          label="model"
          value={candidate}
          onChange={setCandidate}
          options={options}
          popoverWidth={360}
          placeholder={
            pricing.loading
              ? "loading pricing table…"
              : `search ${options.length} models…`
          }
          emptyHint={
            pricing.error
              ? "Pricing table failed to load."
              : pricing.loading
                ? "loading pricing…"
                : "No models match."
          }
          buttonValueRender={(selected) =>
            selected ? (
              <b className="font-mono text-fg-0">{selected.value}</b>
            ) : (
              <span className="font-mono text-fg-3">pick a model…</span>
            )
          }
        />
        <button
          type="button"
          onClick={onForecast}
          disabled={!candidate}
          className="rounded-3 border border-accent bg-accent-soft px-2.5 py-1 text-[11px] font-medium text-accent hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
        >
          Forecast
        </button>
      </div>

      {submitted && (
        <ChartState
          loading={forecast.loading}
          error={forecast.error}
          empty={!forecast.data}
          emptyHint="Forecast unavailable."
          height={80}
        >
          {forecast.data && <ForecastResultPanel data={forecast.data} />}
        </ChartState>
      )}
    </section>
  );
}

// familyOf maps a model id to its family prefix so the dropdown
// can label the row with a muted family chip. Returns "" when the
// id doesn't match a known family - the row renders without the
// chip and the full id shows mono-spaced.
function familyOf(modelId: string): string {
  if (modelId.startsWith("claude-")) return "claude";
  if (modelId.startsWith("gpt-")) return "gpt";
  if (modelId.startsWith("gemini-")) return "gemini";
  if (modelId.startsWith("deepseek")) return "deepseek";
  if (modelId.startsWith("o1") || modelId.startsWith("o3") || modelId.startsWith("o4")) {
    return "openai-o";
  }
  if (modelId.startsWith("babbage") || modelId.startsWith("davinci")) return "openai-legacy";
  if (modelId.startsWith("text-")) return "openai-text";
  if (modelId.startsWith("kilo-")) return "kilo";
  return "";
}

// stripFamilyPrefix removes the family prefix from the model id so
// the dropdown row reads as `claude  opus-4-7-20251001` rather than
// `claude  claude-opus-4-7-20251001`. When family is empty the
// full id is returned untouched.
function stripFamilyPrefix(modelId: string, family: string): string {
  if (!family) return modelId;
  // openai-o / openai-legacy / openai-text are virtual groupings —
  // their model ids don't actually start with the family label. Skip
  // the strip in those cases.
  if (family.startsWith("openai")) return modelId;
  const prefix = family + "-";
  return modelId.startsWith(prefix) ? modelId.slice(prefix.length) : modelId;
}

function ForecastResultPanel({ data }: { data: CacheForecastResponse }) {
  const neverPays = (data.warnings ?? []).includes("switch_never_pays_off");
  return (
    <div className="mt-2 space-y-2 text-[11px]">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <ForecastStat label="Switch cost" value={fmtUSD(data.switch_cost_usd)} />
        <ForecastStat
          label="Break-even"
          value={neverPays ? "never" : `${fmtInt(data.break_even_turns)} turns`}
          warn={neverPays}
        />
        <ForecastStat
          label="Savings / turn"
          value={fmtUSD(data.savings_per_turn_usd)}
          warn={data.savings_per_turn_usd < 0}
        />
        <ForecastStat
          label="Est. net savings"
          value={fmtUSD(data.estimated_net_savings_usd)}
          warn={data.estimated_net_savings_usd < 0}
          sub={`over ${fmtInt(data.estimated_remaining_turns)} more turns`}
        />
        <ForecastStat
          label="Prefix tokens"
          value={fmtCompact(data.current_prefix_tokens)}
          sub={`avg suffix ${fmtCompact(data.avg_suffix_tokens)} / out ${fmtCompact(data.avg_output_tokens)}`}
        />
      </div>
      {(data.warnings ?? []).length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 pt-1">
          {(data.warnings ?? []).map((w) => (
            <ForecastWarningPill key={w} kind={w} />
          ))}
        </div>
      )}
      <div className="text-[10.5px] text-fg-3">
        {data.current_model} → {data.candidate_model} · per-turn{" "}
        {fmtUSD(data.per_turn_before_usd)} → {fmtUSD(data.per_turn_after_usd)}
      </div>
    </div>
  );
}

function ForecastStat({
  label,
  value,
  sub,
  warn,
}: {
  label: string;
  value: string;
  sub?: string;
  warn?: boolean;
}) {
  return (
    <div className="flex flex-col">
      <span className="text-[10px] font-medium uppercase tracking-[0.05em] text-fg-3">
        {label}
      </span>
      <span
        className={clsx(
          "tabular-nums text-[12.5px] font-semibold",
          warn ? "text-warn" : "text-fg-1",
        )}
      >
        {value}
      </span>
      {sub && (
        <span className="mt-0.5 text-[10px] text-fg-3">{sub}</span>
      )}
    </div>
  );
}

function ForecastWarningPill({ kind }: { kind: CacheForecastWarning }) {
  const labels: Record<CacheForecastWarning, string> = {
    cache_wont_engage: "candidate cache won't engage yet",
    fast_mode_active: "current model in fast tier (2×)",
    try_1h_tier: "session has > 5m gaps - try 1h TTL",
    switch_never_pays_off: "switch never recoups cold-write cost",
    empty_prefix: "no cache built yet on this session",
  };
  const variant: "warn" | "neutral" =
    kind === "switch_never_pays_off" || kind === "cache_wont_engage" ? "warn" : "neutral";
  return <Pill variant={variant}>{labels[kind]}</Pill>;
}
