import { KpiBand as SharedKpiBand } from "@shared/components/sessiondetail/KpiBand";
import type { SessionDetail } from "@/lib/types";
import { hasRecordedUsage } from "./shared";

// Compatibility wrapper: the KPI band was promoted into the shared design
// system so the node and org drawers render the same four headline tiles. The
// shared component takes plain numbers/strings; this maps the node's
// SessionDetail onto them and keeps the default (fmtUSD) cost rendering, so the
// node behaviour is unchanged. Existing @/...KpiBand importers are untouched.
//
// usageRecorded carries the node's hasRecordedUsage(d) so the shared tiles can
// distinguish uncaptured usage from a real zero (deployed fix 1896d8dc9): the
// Tokens tile shows "Unknown" / "usage not captured" and the cost tile shows
// "Unknown" with the tokens_note tooltip when usage was not recorded. The org
// omits this prop and is unaffected.
export function KpiBand({ d }: { d: SessionDetail }) {
  const totalTokens =
    d.tokens.input + d.tokens.output + d.tokens.cache_read + d.tokens.cache_creation;
  return (
    <SharedKpiBand
      cost={d.cost_usd}
      aiCost={d.ai_cost_usd}
      toolCost={d.tool_cost_usd}
      totalActions={d.total_actions}
      successActions={d.success_actions}
      failureActions={d.failure_actions}
      totalTokens={totalTokens}
      contextBudgetTokens={d.context_budget_tokens}
      tokensNote={d.tokens_note}
      startedAt={d.started_at}
      endedAt={d.ended_at}
      lastActivityAt={d.last_activity_at}
      usageRecorded={hasRecordedUsage(d)}
    />
  );
}
