import { useEffect, useRef } from "react";
import { useSearchParams } from "react-router-dom";
import { useUrlTab } from "@/lib/useUrlTab";
import {
  Activity,
  BookOpen,
  DollarSign,
  GitCommitHorizontal,
  GitPullRequest,
  LayoutDashboard,
  ListTodo,
  MessageSquareText,
  WandSparkles,
  type LucideIcon,
} from "lucide-react";
import {
  SlideOver,
  TabStrip,
  TruncatedPath,
  type TabDef,
} from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { useApi } from "@/lib/useApi";
import { costLabel, dollarsShown } from "@/lib/format";
import type { ProjectDetail } from "@/lib/types";
import { projectDrawerFilterNote, windowKey, type WindowParams } from "@/lib/projectDrawer";
import { OverviewTab } from "@/components/projectdetail/OverviewTab";
import { SpendTab } from "@/components/projectdetail/SpendTab";
import { CommitsTab } from "@/components/projectdetail/CommitsTab";
import { DeliveryTab } from "@/components/projectdetail/DeliveryTab";
import { PromptsTab } from "@/components/projectdetail/PromptsTab";
import { TasksTab } from "@/components/projectdetail/TasksTab";
import { GuidanceTab } from "@/components/projectdetail/GuidanceTab";
import { SkillsTab } from "@/components/projectdetail/SkillsTab";

// ProjectDetailPanel — the Projects-page list->detail drawer (plan
// docs/plans/projects-page-roi-and-commit-alignment-plan-2026-09-21.md §3.5).
// Mirrors SessionDetailPanel's shell shape (persistent header, a TabStrip,
// per-tab components under components/projectdetail/). The window is the
// page's global window (REVIEW-3 P3-25, T-485): every tab reads the same
// since / until, hours or days the list does, so a closed range in the
// filter bar bounds the drawer too. The routes are project-grain and do not
// narrow by tool or model; a set Tool or Model filter is named in a note.
// Each tab fetches its own data lazily (on first visit),
// simple conditional rendering rather than SessionDetailPanel's
// keep-mounted-hidden pattern — none of these tabs poll live, so losing
// in-flight state on a tab flick costs nothing but one refetch.

// The drawer's tab lives in `?dtab=` (platform tabs plan §2.2: "Projects
// drawer tab to the URL"), beside the page's `?project=`: a REPLACE write
// (a drawer tab is an in-place view, not navigation), the default is the
// param's absence, and an unknown value falls back to Overview.
const TAB_IDS = ["overview", "spend", "commits", "delivery", "prompts", "tasks", "guidance", "skills"] as const;
type TabId = (typeof TAB_IDS)[number];
const TAB_PARAM = "dtab";
// COMMIT_PARAM names the commit the Commits tab opens expanded (a deep link
// from the Delivery tab, `?dtab=commits&sha=<sha>`).
const COMMIT_PARAM = "sha";

// One glyph per project-detail tab. Tasks shares ListTodo with the session
// drawer's Tasks tab on purpose: the same concept keeps the same icon.
const TAB_ICONS: Record<TabId, LucideIcon> = {
  overview: LayoutDashboard,
  spend: DollarSign,
  commits: GitCommitHorizontal,
  delivery: GitPullRequest,
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
    { id: "delivery", label: "Delivery" },
    { id: "prompts", label: "Prompts" },
    { id: "tasks", label: "Tasks" },
    { id: "guidance", label: "Guidance" },
    { id: "skills", label: "Skills" },
  ] as const
).map((t) => ({ ...t, icon: TAB_ICONS[t.id] }));

// viewTabs names the Spend tab under the developer cost display: in the
// org's token-usage view (format.ts cost affordances) it shows turns and
// counts only, so it is "Activity" with a non-dollar glyph. Resolved at
// render: the display mode is set after this module loads.
function viewTabs(): TabDef<TabId>[] {
  if (dollarsShown()) return TABS;
  return TABS.map((t) => (t.id === "spend" ? { ...t, label: costLabel("Spend", "Activity"), icon: Activity } : t));
}

export function ProjectDetailPanel({
  projectId,
  open,
  onClose,
  win,
  tool,
  model,
}: {
  projectId: number | null;
  open: boolean;
  onClose: () => void;
  /** The page's global window (windowParams of the filter bar). */
  win: WindowParams;
  tool?: string;
  model?: string;
}) {
  const [tab, setTab] = useUrlTab(TAB_IDS, "overview", { param: TAB_PARAM, history: "replace" });
  const [searchParams, setSearchParams] = useSearchParams();
  const hasTabParam = searchParams.has(TAB_PARAM);

  // A clean landing state for every project: closing the drawer drops
  // `?dtab=` (so opening project B after leaving A on Commits lands on
  // Overview), and switching straight from one project to another resets it.
  // A cold deep link (`?project=5&dtab=commits`) keeps its tab.
  useEffect(() => {
    if (open || !hasTabParam) return;
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.delete(TAB_PARAM);
        next.delete(COMMIT_PARAM);
        return next;
      },
      { replace: true },
    );
  }, [open, hasTabParam, setSearchParams]);
  const prevProject = useRef<number | null>(projectId);
  useEffect(() => {
    const prev = prevProject.current;
    prevProject.current = projectId;
    if (prev != null && projectId != null && prev !== projectId) setTab("overview");
  }, [projectId, setTab]);

  const detail = useApi<ProjectDetail>(
    projectId != null ? `/api/project/${projectId}` : null,
    { ...win },
    [projectId, windowKey(win)],
  );
  const d = detail.data;
  const filterNote = projectDrawerFilterNote(tool, model);

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
        </div>
        {filterNote ? <div className="mb-3 text-[11px] text-fg-3">{filterNote}</div> : null}

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
              tabs={viewTabs()}
              value={tab}
              onChange={setTab}
              idPrefix="projectdetail"
              className="mt-2"
            />

            <div className="mt-5">
              {tab === "overview" && <OverviewTab d={d} onReload={detail.reload} />}
              {tab === "spend" && <SpendTab projectId={d.project.id} win={win} />}
              {tab === "commits" && <CommitsTab projectId={d.project.id} win={win} />}
              {tab === "delivery" && (
                <DeliveryTab
                  projectId={d.project.id}
                  win={win}
                  onOpenTab={setTab}
                  onOpenCommit={(sha) =>
                    setSearchParams(
                      (prev) => {
                        const next = new URLSearchParams(prev);
                        next.set(TAB_PARAM, "commits");
                        next.set(COMMIT_PARAM, sha);
                        return next;
                      },
                      { replace: true },
                    )
                  }
                />
              )}
              {tab === "prompts" && <PromptsTab projectId={d.project.id} win={win} />}
              {tab === "tasks" && <TasksTab projectId={d.project.id} win={win} />}
              {tab === "guidance" && <GuidanceTab root={d.project.root_path} />}
              {tab === "skills" && <SkillsTab projectId={d.project.id} win={win} />}
            </div>
          </>
        )}
      </div>
    </SlideOver>
  );
}
