import { useApi } from "@/lib/useApi";
import { fmtBytes, fmtUSD } from "@/lib/format";
import { HelpInd } from "@/components/HelpInd";
import { ChartState } from "@/components/ChartState";
import type { VerbosityResponse } from "@/lib/types";
import { Link } from "react-router-dom";

// VerbosityCard — the Output Composition (Verbosity) session card
// (docs/plans/output-composition-verbosity-plan-2026-06-30.md). Shows how
// much of a session's assistant output is narrative explanation vs shown
// (fenced) artifacts vs authored code (file writes + shell commands), by
// language. Read-side over actions.raw_tool_output (visible text, segmented
// at read time) + actions.content_bytes (authored code).
export function VerbosityCard({ sessionId }: { sessionId: string }) {
  const v = useApi<VerbosityResponse>(
    `/api/session/${sessionId}/verbosity`,
    undefined,
    [sessionId],
  );

  const data = v.data;
  const has = data && data.total_bytes > 0;

  return (
    <section className="mt-5 rounded-3 border bg-bg-2 px-4 py-3">
      <div className="flex items-center justify-between gap-2">
        <span className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          Output composition
          <HelpInd id="card.verbosity" />
        </span>
        {has && (
          <span className="text-[10px] tabular-nums text-fg-3">
            code {Math.round(data.code_pct)}% · explain{" "}
            {Math.round(data.explain_pct)}%
            {data.code_explain_ratio != null &&
              ` · ${data.code_explain_ratio.toFixed(2)}×`}
          </span>
        )}
      </div>
      <p className="mt-1 text-[10.5px] text-fg-3">
        How much of this session's assistant output is explanation vs authored
        code (file writes + shell commands) and shown snippets, by language.
      </p>

      <ChartState
        loading={v.loading && !v.data}
        error={v.error}
        empty={!has}
        emptyHint="No assistant output captured yet."
        height={80}
      >
        {has && <VerbosityBody data={data} />}
      </ChartState>
    </section>
  );
}

// CAT_COLOR maps a content category to a bar/legend colour. Tokens match the
// palette used by the other cards (bg-info / success / warn / danger / fg-3).
const CAT_COLOR: Record<string, string> = {
  code: "bg-info",
  prose: "bg-fg-3",
  docs: "bg-success",
  config: "bg-warn",
  data: "bg-danger",
  unknown: "bg-fg-2/40",
};

function VerbosityBody({ data }: { data: VerbosityResponse }) {
  const total = data.total_bytes;
  const cats = Object.entries(data.by_category)
    .filter(([, b]) => b > 0)
    .sort((a, b) => b[1] - a[1]);

  return (
    <div className="space-y-2.5">
      {/* stacked category bar */}
      <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-bg-1">
        {cats.map(([cat, b]) => (
          <div
            key={cat}
            className={CAT_COLOR[cat] ?? "bg-fg-3"}
            style={{ width: `${(b / total) * 100}%` }}
            title={`${cat}: ${fmtBytes(b)} (${((b / total) * 100).toFixed(1)}%)`}
          />
        ))}
      </div>

      {/* category legend */}
      <div className="flex flex-wrap gap-x-3 gap-y-1 text-[10px]">
        {cats.map(([cat, b]) => (
          <span key={cat} className="flex items-center gap-1 text-fg-2">
            <span className={`size-2 rounded-sm ${CAT_COLOR[cat] ?? "bg-fg-3"}`} />
            {cat} {Math.round((b / total) * 100)}%
          </span>
        ))}
      </div>

      {/* channels */}
      <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-[10.5px] text-fg-3">
        <ChannelRow label="narrative prose" v={data.channels.narrative_bytes} total={total} />
        <ChannelRow label="shown artifacts" v={data.channels.artifact_bytes} total={total} />
        <ChannelRow label="code written" v={data.channels.written_bytes} total={total} />
        <ChannelRow label="shell commands" v={data.channels.command_bytes} total={total} />
      </div>

      {/* code by language */}
      {data.code_by_language.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {data.code_by_language.slice(0, 10).map((l) => (
            <span
              key={l.language}
              className="rounded-2 bg-bg-1 px-1.5 py-0.5 text-[10px] text-fg-2"
            >
              {l.language}{" "}
              <span className="tabular-nums text-fg-3">
                {fmtBytes(l.bytes)} · {pct(l.bytes, total)}%
              </span>
            </span>
          ))}
        </div>
      )}

      {/* estimated token/$ split (plan §7) */}
      {data.cost_estimated && <VerbosityCost data={data} />}

      {!data.authored_captured && (
        <p className="rounded-2 border border-warn/30 bg-warn/10 px-2 py-1.5 text-[10px] text-warn">
          Authored-code bytes are missing for {data.authored_total_actions} write/edit/command actions in this session.{" "}
          <Link
            to={data.backfill_settings_url || "/settings?section=backfill"}
            className="font-medium text-accent hover:underline"
          >
            Run Backfill
          </Link>{" "}
          with the current SuperBased build, then refresh this session.
        </p>
      )}
    </div>
  );
}

function ChannelRow({
  label,
  v,
  total,
}: {
  label: string;
  v: number;
  total: number;
}) {
  return (
    <span className="flex justify-between gap-2">
      <span>{label}</span>
      <span className="tabular-nums text-fg-2">
        {fmtBytes(v)} <span className="text-fg-3">· {pct(v, total)}%</span>
      </span>
    </span>
  );
}

// pct renders bytes as a whole-number percentage of total (0 when total is 0).
function pct(bytes: number, total: number): number {
  return total > 0 ? Math.round((bytes / total) * 100) : 0;
}

// VerbosityCost renders the ESTIMATED token/$ attribution (plan §7). Bytes are
// exact; this split apportions the session's output tokens across content types
// and prices them at the model's output rate, so it is always labelled "est."
function VerbosityCost({ data }: { data: VerbosityResponse }) {
  return (
    <div className="border-t border-border pt-2 text-[10.5px]">
      <div className="flex items-center justify-between text-fg-3">
        <span>
          est. cost
          {data.model && <span className="text-fg-3/70"> · {data.model}</span>}
        </span>
        <span className="tabular-nums text-fg-2">
          {fmtUSD(data.est_total_usd, true)} total
        </span>
      </div>
      <div className="mt-0.5 flex flex-wrap gap-x-3 gap-y-0.5 text-fg-3">
        <span>
          code{" "}
          <span className="tabular-nums text-info">
            {fmtUSD(data.est_code_usd, true)}
          </span>
        </span>
        <span>
          explain{" "}
          <span className="tabular-nums text-fg-2">
            {fmtUSD(data.est_explain_usd, true)}
          </span>
        </span>
        {!!data.est_reasoning_tokens && (
          <span className="text-fg-3/70">
            reasoning {data.est_reasoning_tokens.toLocaleString()} tok
          </span>
        )}
      </div>
      <p className="mt-0.5 text-[9.5px] text-fg-3/70">
        est. - output tokens apportioned by content type, priced at the model's
        output rate. Bytes above are exact.
      </p>
    </div>
  );
}
