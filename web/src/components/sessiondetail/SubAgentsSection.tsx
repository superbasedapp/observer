import { useCallback, useState } from "react";
import { SubAgentsSection as SharedSubAgentsSection } from "@shared/components/sessiondetail/SubAgentsSection";
import type { SubAgentLike } from "@shared/lib/types";
import { fetchJSON } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import type { ActionFullText } from "@/lib/types";

// Compatibility wrapper: the Sub-agents section was promoted into the shared
// design system so the node and org session-detail drawers render the same
// rows. The shared component is pure — it owns no data state, no persistence
// and no fetch; this wrapper keeps all three node-side:
//   * the open/closed state persisted in localStorage,
//   * the lazy GET /api/session/<id>/subagents (a closed section makes NO
//     request — useApi skips null paths),
//   * the /api/action/<id>/full_text loader for a hook-only row.
// The cost text stays on the shared default (≈$x.xx with the exact value on
// hover), so node behaviour is unchanged. Existing importers are untouched.

const SECTION_OPEN_KEY = "sb_subagents_section_open";

type SessionSubagentsResponse = {
  session_id: string;
  total: number;
  subagents: SubAgentLike[];
};

export function SubAgentsSection({ sessionId }: { sessionId: string | null }) {
  const [open, setOpen] = useState<boolean>(() => {
    try {
      return localStorage.getItem(SECTION_OPEN_KEY) === "1";
    } catch {
      return false;
    }
  });
  const toggleOpen = useCallback(() => {
    setOpen((v) => {
      const next = !v;
      try {
        localStorage.setItem(SECTION_OPEN_KEY, next ? "1" : "0");
      } catch {
        /* ignore */
      }
      return next;
    });
  }, []);

  // Lazy-load: only fetch once the section is open. A closed section makes
  // no request (useApi skips null paths).
  const subs = useApi<SessionSubagentsResponse>(
    open && sessionId ? `/api/session/${sessionId}/subagents` : null,
    undefined,
    [sessionId, open],
  );
  const data = subs.data;

  return (
    <SharedSubAgentsSection
      open={open}
      onToggleOpen={toggleOpen}
      rows={data?.subagents ?? []}
      total={data?.total}
      loaded={Boolean(data)}
      loading={subs.loading}
      error={subs.error}
      fetchFullText={(id) =>
        fetchJSON<ActionFullText>(`/api/action/${id}/full_text`)
      }
    />
  );
}
