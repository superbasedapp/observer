import { CoverageBadge, ExecutionLocationBadge, Pill, Table, Tooltip } from "@/components/primitives";
import { HelpInd } from "@/components/HelpInd";
import { windowKey, type WindowParams } from "@/lib/projectDrawer";
import { useApi } from "@/lib/useApi";
import { dollarsShown, fmtCompact, fmtInt, fmtUSD } from "@/lib/format";
import {
  accountCoverage,
  costCoverageLabel,
  laneShown,
  ledgerCoverageLabel,
  ledgerProvenance,
  ledgerValue,
  tokenCoverageLabel,
  tokenProvenance,
  type CoverageLabel,
} from "@/lib/cloudLane";
import type { CloudLaneBucket, CloudLaneResponse } from "@/lib/types";

// CloudLane: the Projects detail "Where it ran" lane (cloud-agents lane
// CA-B5, plan section 8). It splits the project's sessions by where each
// agent ran (this machine, a vendor's cloud sandbox, a worker the
// organization runs, or unknown) and shows, per lane, the figures each rail
// actually reported with a coverage badge on every one. A figure nothing
// reported is "not reported", never a zero. Provider units (ACUs, credits,
// quota) stay in their own unit on the Spend view, never folded into dollars.
//
// Two views of the same GET /api/project/<id>/cloud payload: "overview"
// (sessions and tokens) and "spend" (dollars and provider usage). It renders
// nothing for a project that never ran anywhere else, so a node with no
// cloud agents sees both tabs exactly as before.

export type CloudLaneViewKind = "overview" | "spend";

export function CloudLane({ projectId, win, view }: { projectId: number; win: WindowParams; view: CloudLaneViewKind }) {
  const lane = useApi<CloudLaneResponse>(`/api/project/${projectId}/cloud`, { ...win }, [projectId, windowKey(win)]);
  // A failed or denied lane read hides the lane: the rest of the tab is
  // complete without it, and an error box here would read as a page fault.
  if (!lane.data || !laneShown(lane.data)) return null;
  return <CloudLaneView data={lane.data} view={view} />;
}

function Coverage({ c }: { c: CoverageLabel }) {
  return (
    <CoverageBadge status={c.status} detail={c.detail}>
      {c.label}
    </CoverageBadge>
  );
}

function LocationCell({ b }: { b: CloudLaneBucket }) {
  if (b.location === "unknown") {
    return (
      <Tooltip content="Nothing recorded where these sessions ran. They are not assumed local.">
        <span tabIndex={0} className="text-[11px] text-fg-3 focus:outline-none">
          unknown
        </span>
      </Tooltip>
    );
  }
  return <ExecutionLocationBadge location={b.location} />;
}

function TokensCell({ b }: { b: CloudLaneBucket }) {
  const prov = tokenProvenance(b);
  return (
    <div className="flex flex-col items-end gap-0.5">
      <span className="tabular-nums text-fg-1">{b.tokens ? fmtCompact(b.tokens.total) : "not reported"}</span>
      <Coverage c={tokenCoverageLabel(b)} />
      {prov && <span className="text-[10.5px] text-fg-4">{prov}</span>}
    </div>
  );
}

function SpendCell({ b }: { b: CloudLaneBucket }) {
  return (
    <div className="flex flex-col items-end gap-0.5">
      <span className="tabular-nums text-fg-1">{b.cost_usd != null ? fmtUSD(b.cost_usd) : "not reported"}</span>
      <Coverage c={costCoverageLabel(b)} />
    </div>
  );
}

function LedgerCell({ b }: { b: CloudLaneBucket }) {
  const figures = b.ledger ?? [];
  if (figures.length === 0) {
    return <span className="text-[11px] text-fg-4">{b.location === "vendor_cloud" || b.location === "customer_worker" ? "none reported" : "-"}</span>;
  }
  return (
    <ul className="flex flex-col items-end gap-1">
      {figures.map((f) => (
        <li key={`${f.connector}|${f.unit}|${f.value_type}|${f.measurement_source}|${f.monetary_status}`} className="flex flex-col items-end gap-0.5">
          <span className="tabular-nums text-fg-1">{ledgerValue(f)}</span>
          <span className="text-[10.5px] text-fg-4">{ledgerProvenance(f)}</span>
          <Coverage c={ledgerCoverageLabel(f, b)} />
        </li>
      ))}
    </ul>
  );
}

export function CloudLaneView({ data, view }: { data: CloudLaneResponse; view: CloudLaneViewKind }) {
  const twins = data.projects.filter((p) => p.synthetic && p.id !== data.projects[0]?.id);
  const showDollars = dollarsShown();
  return (
    <section aria-label="Where it ran" className="space-y-2">
      <h3 className="flex items-center text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
        Where it ran
        <HelpInd id="glossary.projects_where_it_ran" />
      </h3>
      {data.folded_into && (
        <p className="rounded-2 border border-line-2 bg-bg-2 px-3 py-2 text-[11px] text-fg-3">
          This cloud project now groups under the local project{" "}
          <span className="font-mono text-fg-1">{data.folded_into.root_path}</span>, which shows both together.
        </p>
      )}
      {twins.length > 0 && (
        <p className="text-[11px] text-fg-3">
          Includes cloud sessions filed under{" "}
          {twins.map((t, i) => (
            <span key={t.id}>
              {i > 0 && ", "}
              <span className="font-mono text-fg-1">{t.root_path}</span>
            </span>
          ))}
          , the same repository with no local checkout. The project's Spend total counts them too.
        </p>
      )}
      {(data.superseded_turns ?? 0) > 0 && (
        <p className="text-[11px] text-fg-3">
          {data.superseded_turns === 1 ? "1 turn" : `${fmtInt(data.superseded_turns!)} turns`} set aside: a better capture rail
          reported the same session, so only the best report counts (never both).
        </p>
      )}
      <Table
        head={
          <tr>
            <th className="py-1.5 pl-1 font-medium">Ran</th>
            <th className="py-1.5 text-right font-medium">Sessions</th>
            {view === "overview" && <th className="py-1.5 pr-1 text-right font-medium">Tokens</th>}
            {view === "spend" && showDollars && <th className="py-1.5 text-right font-medium">Spend</th>}
            {view === "spend" && !showDollars && <th className="py-1.5 text-right font-medium">Tokens</th>}
            {view === "spend" && <th className="py-1.5 pr-1 text-right font-medium">Provider usage</th>}
          </tr>
        }
      >
        {data.buckets.map((b) => (
          <tr key={b.location} className="border-b border-line-1 align-top last:border-0">
            <td className="py-1.5 pl-1">
              <LocationCell b={b} />
            </td>
            <td className="py-1.5 text-right tabular-nums text-fg-1">{fmtInt(b.sessions)}</td>
            {view === "overview" && (
              <td className="py-1.5 pr-1 text-right">
                <TokensCell b={b} />
              </td>
            )}
            {view === "spend" && (
              <td className="py-1.5 text-right">{showDollars ? <SpendCell b={b} /> : <TokensCell b={b} />}</td>
            )}
            {view === "spend" && (
              <td className="py-1.5 pr-1 text-right">
                <LedgerCell b={b} />
              </td>
            )}
          </tr>
        ))}
      </Table>
      {view === "spend" && data.ledger_truncated && (
        <p className="text-[11px] text-warn">
          Only the newest 5,000 provider usage reports were read for this window, so provider figures are partial.
        </p>
      )}
      {(data.accounts?.length ?? 0) > 0 && (
        <div className="flex flex-wrap items-center gap-2 text-[11px] text-fg-3">
          <span>Cloud connectors:</span>
          {data.accounts!.map((a) => {
            const c = accountCoverage(a.coverage_state);
            return (
              <span key={`${a.connector}|${a.provider}`} className="inline-flex items-center gap-1">
                <Pill case="none">{a.connector}</Pill>
                <CoverageBadge status={c.status} detail={a.last_error_class ? `Last error: ${a.last_error_class.replace(/_/g, " ")}` : undefined}>
                  {c.label}
                </CoverageBadge>
              </span>
            );
          })}
        </div>
      )}
    </section>
  );
}
