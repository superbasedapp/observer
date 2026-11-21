import { Fragment } from "react";
import { CoverageBadge, Tooltip } from "@/components/primitives";
import { executionLocationLabel } from "@shared/primitives/ExecutionLocationBadge";
import { fmtCompact, fmtUSD } from "@/lib/format";
import { ledgerProvenance, ledgerValue, type SpendSplit } from "@/lib/cloudLane";

// SpendSplitLine: a folded project Spend total broken down by where it ran
// (cloud-agents lane CA-C1, decision CA-D21). It sits under the Overview
// Spend tile and in the Spend tab header so the one total and its local /
// cloud / worker / unknown parts read together. A part nothing priced reads
// "not reported", never $0.00; a part whose dollars are a floor carries a
// marker, and any such part labels the whole total partial. Provider usage
// (ACUs, credits, premium requests) is listed beside the dollars in its own
// unit and is never converted or added to them. Turns the CA-D12 precedence
// set aside are explained by the "Where it ran" lane below, not here.

export function SpendSplitLine({ split, showDollars }: { split: SpendSplit; showDollars: boolean }) {
  return (
    <span className="flex flex-col gap-0.5" aria-label="Spend by where it ran">
      <span className="flex flex-wrap items-center gap-x-1">
        {split.parts.map((p, i) => {
          const value = showDollars
            ? p.cost_usd != null
              ? fmtUSD(p.cost_usd)
              : "not reported"
            : p.tokens != null
              ? `${fmtCompact(p.tokens)} tokens`
              : "not reported";
          const incomplete = showDollars && p.cost.status !== "full";
          return (
            <Fragment key={p.location}>
              {i > 0 && <span className="text-fg-4">·</span>}
              <Tooltip content={showDollars ? `${p.cost.label}: ${p.cost.detail}` : undefined}>
                <span tabIndex={showDollars ? 0 : undefined} className="whitespace-nowrap focus:outline-none">
                  <span className="text-fg-3">{executionLocationLabel(p.location)}</span>{" "}
                  <span className="tabular-nums text-fg-1">{value}</span>
                  {incomplete && p.cost_usd != null && <span className="ml-0.5 text-warn">*</span>}
                </span>
              </Tooltip>
            </Fragment>
          );
        })}
        {showDollars && split.partial && (
          <CoverageBadge
            status="partial"
            detail="At least one location's dollars are missing or cover only some of its sessions or turns, so the total is a floor. Hover a location for why."
          >
            partial total
          </CoverageBadge>
        )}
      </span>
      {split.usage.length > 0 && (
        <span className="text-[10.5px] text-fg-3">
          Provider usage, own units (not in the dollar total):{" "}
          {split.usage.map((u, i) => (
            <Fragment key={`${u.location}|${u.figure.connector}|${u.figure.unit}|${u.figure.value_type}|${u.figure.measurement_source}|${u.figure.monetary_status}`}>
              {i > 0 && ", "}
              <Tooltip content={ledgerProvenance(u.figure)}>
                <span tabIndex={0} className="whitespace-nowrap focus:outline-none">
                  {executionLocationLabel(u.location)} <span className="tabular-nums text-fg-1">{ledgerValue(u.figure)}</span>
                </span>
              </Tooltip>
            </Fragment>
          ))}
        </span>
      )}
      {split.folded.length > 0 && (
        <span className="text-[10.5px] text-fg-4">
          Includes{" "}
          {split.folded.map((root, i) => (
            <Fragment key={root}>
              {i > 0 && ", "}
              <span className="font-mono">{root}</span>
            </Fragment>
          ))}
        </span>
      )}
    </span>
  );
}
