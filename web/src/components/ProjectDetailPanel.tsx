import { useEffect, useState } from "react";
import {
  BookOpen,
  DollarSign,
  GitCommitHorizontal,
  LayoutDashboard,
  ListTodo,
  MessageSquareText,
  WandSparkles,
  type LucideIcon,
} from "lucide-react";
import {
  SegmentedControl,
  SlideOver,
  TabStrip,
  TruncatedPath,
  type TabDef,
} from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { useApi } from "@/lib/useApi";
import type { ProjectDetail } from "@/lib/types";
import { OverviewTab } from "@/components/projectdetail/OverviewTab";
import { SpendTab } from "@/components/projectdetail/SpendTab";
import { CommitsTab } from "@/components/projectdetail/CommitsTab";
import { PromptsTab } from "@/components/projectdetail/PromptsTab";
import { TasksTab } from "@/components/projectdetail/TasksTab";
import { GuidanceTab } from "@/components/projectdetail/GuidanceTab";
import { SkillsTab } from "@/components/projectdetail/SkillsTab";

// ProjectDetailPanel — the Projects-page list->detail drawer (plan
// docs/plans/projects-page-roi-and-commit-alignment-plan-2026-09-21.md §3.5).
// Mirrors SessionDetailPanel's shell shape (persistent header + window
// picker, a TabStrip, per-tab components under components/projectdetail/)
// but keeps the active tab in LOCAL state rather than the URL — this panel
// is deep-linked only by `?project=<id>` (the Projects page's own route
// state), and a second `?tab=` slot would collide with the one
// SessionDetailPanel already owns should both ever be open at once via
// cross-navigation. Each tab fetches its own data lazily (on first visit),
// simple conditional rendering rather than SessionDetailPanel's
// keep-mounted-hidden pattern — none of these tabs poll live, so losing
// in-flight state on a tab flick costs nothing but one refetch.

type TabId = "overview" | "spend" | "commits" | "prompts" | "tasks" | "guidance" | "skills";

// One glyph per project-detail tab. Tasks shares ListTodo with the session
// drawer's Tasks tab on purpose: the same concept keeps the same icon.
const TAB_ICONS: Record<TabId, LucideIcon> = {
  overview: LayoutDashboard,
  spend: DollarSign,
  commits: GitCommitHorizontal,
  prompts: MessageSquareText,
  tasks: ListTodo,
  guidance: BookOpen,
  skills: WandSparkles,
};

const TABS: TabDef<TabId>[] = (
  [
    { id: "overview", label: "Overview" },
    { id: "spend", label: "Spend" },
    { id: "commits", label: "Commits" },
    { id: "prompts", label: "Prompts" },
    { id: "tasks", label: "Tasks" },
    { id: "guidance", label: "Guidance" },
    { id: "skills", label: "Skills" },
  ] as const
).map((t) => ({ ...t, icon: TAB_ICONS[t.id] }));

const WINDOW_OPTIONS = [
  { value: "7", label: "7d" },
  { value: "30", label: "30d" },
  { value: "90", label: "90d" },
] as const;

export function ProjectDetailPanel({
  projectId,
  open,
  onClose,
}: {
  projectId: number | null;
  open: boolean;
  onClose: () => void;
}) {
  const [tab, setTab] = useState<TabId>("overview");
  const [days, setDays] = useState(30);

  // Reset to a clean landing state whenever a DIFFERENT project opens —
  // otherwise closing project A on the Commits tab and opening project B
  // would land straight on B's Commits tab.
  useEffect(() => {
    if (projectId != null) {
      setTab("overview");
    }
  }, [projectId]);

  const detail = useApi<ProjectDetail>(
    projectId != null ? `/api/project/${projectId}` : null,
    { days },
    [projectId, days],
  );
  const d = detail.data;

  return (
    <SlideOver
      open={open}
      onClose={onClose}
      width={960}
      title={
        d ? (
          <TruncatedPath
            value={d.project.name || d.project.root_path}
            className="max-w-[560px] font-mono"
          />
        ) : (
          "Project"
        )
      }
      subtitle={
        d?.project.name ? (
          <TruncatedPath value={d.project.root_path} className="text-[11px]" />
        ) : undefined
      }
    >
      <div className="px-5 pb-5 pt-3">
        <div className="mb-3 flex items-center justify-between gap-3">
          <div className="text-[11px] text-fg-3">
            {d ? `${d.project.tools.join(", ") || "no tools recorded"}` : " "}
          </div>
          <SegmentedControl
            options={WINDOW_OPTIONS.map((o) => ({ value: o.value, label: o.label }))}
            value={String(days)}
            onChange={(v) => setDays(Number(v))}
            size="sm"
          />
        </div>

        <ChartState
          loading={!detail.data && !detail.error && (detail.loading || projectId == null)}
          error={detail.error}
          denied={detail.denied}
          deniedPermission={detail.deniedPermission}
          onRetry={detail.reload}
          empty={!detail.data}
          emptyHint="No detail for this project"
          kind="list"
          height={120}
        >
          {null}
        </ChartState>

        {d && (
          <>
            <TabStrip
              tabs={TABS}
              value={tab}
              onChange={setTab}
              idPrefix="projectdetail"
              className="mt-2"
            />

            <div className="mt-5">
              {tab === "overview" && <OverviewTab d={d} />}
              {tab === "spend" && <SpendTab projectId={d.project.id} days={days} />}
              {tab === "commits" && <CommitsTab projectId={d.project.id} days={days} />}
              {tab === "prompts" && <PromptsTab projectId={d.project.id} days={days} />}
              {tab === "tasks" && <TasksTab projectId={d.project.id} days={days} />}
              {tab === "guidance" && <GuidanceTab root={d.project.root_path} />}
              {tab === "skills" && <SkillsTab projectId={d.project.id} days={days} />}
            </div>
          </>
        )}
      </div>
    </SlideOver>
  );
}
