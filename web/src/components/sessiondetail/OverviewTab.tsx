import { NeedsSettingLink } from "@/components/NeedsSettingNotice";
import { placeLink } from "@/lib/settingsPlaces";
import { memo } from "react";
import { ActionBreakdownDonut } from "@/components/charts";
import {
  ModelsUsedPanel,
  RequestClassesPanel,
  TokenBucketsPanel,
} from "@shared/components/sessiondetail";
import { SessionLOCCard } from "@/components/SessionLOCCard";
import { SessionCommitsCard } from "@/components/SessionCommitsCard";
import { VerbosityCard } from "@/components/VerbosityCard";
import { CloudRow } from "@/components/sessiondetail/CloudRow";
import { OrgIntelCard } from "@/components/sessiondetail/OrgIntelCard";
import { SessionQualityCard } from "@/components/sessiondetail/SessionQualityCard";
import { PromptGuardLine } from "@/components/PromptGuardLine";
import type { SessionDetail } from "@/lib/types";
import { hasRecordedUsage } from "./shared";

// Overview tab — "what shape was this session?".
//
// Action breakdown + token buckets + models used + output composition. The two
// pure sub-panels (TokenBucketsPanel, ModelsUsedPanel) were promoted into the
// shared design system so the node and org drawers render them identically;
// they keep their default (fmtUSD) cost rendering here. The tab WRAPPER stays
// node-side because it composes the fetch-coupled LOC / Verbosity / Cloud
// cards.

// Memoized: the drawer re-renders on every detail poll (and on each poll's
// fetching flip). `d` keeps its identity while the detail is unchanged (the
// query cache shares unchanged subtrees), so an idle poll skips this tab.
export const OverviewTab = memo(function OverviewTab({ d }: { d: SessionDetail }) {
  return (
    <div className="space-y-5">
      <CloudRow key={d.id} sessionId={d.id} />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 xl:grid-cols-3">
        <ActionBreakdownDonut rows={d.tool_breakdown} total={d.total_actions} />
        {hasRecordedUsage(d) ? <TokenBucketsPanel tokens={d.tokens} /> : (
          <section className="rounded-3 border border-line-2 bg-bg-2 p-4">
            <h4 className="text-[12px] font-semibold text-fg-1">Token buckets</h4>
            <p className="mt-2 text-[11.5px] text-fg-3">
              Input, output, cache read and cache write counts were not captured for this session. Some tools never record
              them; for a tool that can route through the proxy, set that up in Settings &gt; Connected tools.{" "}
              <NeedsSettingLink link={placeLink("connected_tools")} />
            </p>
          </section>
        )}
        <ModelsUsedPanel rows={d.per_model} totalCost={d.cost_usd} />
      </div>
      {/* GET /api/session/<id> has carried request_class_split since the
          request-class lane; the org drawer rendered it and the node did not.
          Renders nothing when no counted turn carried a class. */}
      <RequestClassesPanel split={d.request_class_split} />
      <SessionQualityCard sessionId={d.id} />
      <SessionLOCCard sessionId={d.id} />
      <SessionCommitsCard sessionId={d.id} />
      <VerbosityCard sessionId={d.id} />
      <OrgIntelCard sessionId={d.id} />
      <PromptGuardLine sessionId={d.id} />
    </div>
  );
});
