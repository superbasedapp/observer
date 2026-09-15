import { TasksTab as SharedTasksTab } from "@shared/components/sessiondetail/TasksTab";
import { useApi } from "@/lib/useApi";
import { hasRecordedUsage } from "./shared";
import type { SessionDetail, SessionTaskReport } from "@/lib/types";

// Compatibility wrapper: the Tasks tab was promoted into the shared design
// system so the node and org session-detail drawers render the same table. The
// shared component is pure — it takes the already-loaded report; this wrapper
// keeps the node's GET /api/session/<id>/tasks fetch (and its
// `token_usage_available ?? hasRecordedUsage(d)` fallback) node-side and leaves
// the cost cells on their default (fmtTaskUSD), so node behaviour is unchanged.
// Existing @/components/sessiondetail/TasksTab importers are untouched.
export function TasksTab({ d }: { d: SessionDetail }) {
  const tasks = useApi<SessionTaskReport>(
    `/api/session/${d.id}/tasks`,
    undefined,
    [d.id],
  );

  return (
    <SharedTasksTab
      report={tasks.data}
      loading={tasks.loading}
      error={tasks.error}
      usageAvailable={tasks.data?.token_usage_available ?? hasRecordedUsage(d)}
    />
  );
}
