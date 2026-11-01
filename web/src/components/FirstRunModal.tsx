import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { FolderGit2, History, LoaderCircle, Plug } from "lucide-react";
import {
  Button,
  EmptyState,
  ErrorState,
  Icon,
  LiveDot,
  Meter,
  Modal,
  Pill,
  Skeleton,
  SuccessCheck,
  ToolGlyphFrame,
  ToolStack,
  TruncatedPath,
} from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import { fetchJSON, localConfirmHeaders } from "@/lib/api";
import {
  FIRST_RUN_PATH,
  FIRST_RUN_POLL_MS,
  FIRST_RUN_SEEN_PATH,
  captureChips,
  closeFirstRun,
  closeMarksSeen,
  firstRunView,
  toolBadge,
  markClosedThisVisit,
  progressRatio,
  seenRequestInit,
  shouldPoll,
  type FirstRunProject,
  type FirstRunResponse,
  type FirstRunTool,
  type FirstRunView,
} from "@/lib/firstRun";

// FirstRunModal - the first-run capture dialog (T-922), lazy-loaded by
// FirstRunHost (which takes the auto-open decision in the shell). It shows
// the AI tools found on this machine, how each one is captured, and the live
// progress of the watcher's first pass over their existing history (GET
// /api/firstrun, read every few seconds while open and still moving). The
// pure half (view model, the open/close store, the seen POST) is
// lib/firstRun.ts.
//
// Closing mid-capture hides it for this visit only, so the next visit shows
// the outcome; closing after the capture finished, or "Don't show this
// again", records it as seen on the daemon (beside its database), so every
// browser agrees. Reopen it from the command palette or Settings, Connected
// tools. The first-visit product tour waits until this is closed
// (components/tour/TourProvider.tsx reads the same store).

function visitStorage(): Storage | null {
  try {
    return typeof window === "undefined" ? null : window.sessionStorage;
  } catch {
    return null;
  }
}

async function postSeen(seen: boolean, minted?: string): Promise<boolean> {
  try {
    const token = minted || (await localConfirmHeaders())["X-Observer-Confirm"];
    await fetchJSON(FIRST_RUN_SEEN_PATH, undefined, seenRequestInit(seen, token ?? ""));
    return true;
  } catch {
    return false;
  }
}

export function FirstRunModal({ open }: { open: boolean }) {
  const [moving, setMoving] = useState(true);
  const res = useApi<FirstRunResponse>(open ? FIRST_RUN_PATH : null, undefined, [], {
    refreshMs: open && moving ? FIRST_RUN_POLL_MS : 0,
  });
  const data = res.data;

  useEffect(() => {
    setMoving(shouldPoll(data));
  }, [data]);

  const close = useCallback(() => {
    if (closeMarksSeen(data) && !data?.seen) {
      void postSeen(true, data?.confirm_token);
    } else {
      markClosedThisVisit(visitStorage());
    }
    closeFirstRun();
  }, [data]);

  const dontShowAgain = useCallback(() => {
    markClosedThisVisit(visitStorage());
    void postSeen(true, data?.confirm_token);
    closeFirstRun();
  }, [data]);

  const navigate = useNavigate();
  const openTools = useCallback(() => {
    close();
    navigate("/settings?section=tools");
  }, [close, navigate]);

  const view = firstRunView({ data, loading: res.loading, error: res.error });
  const done = view.kind === "ready" && view.phase === "done";

  return (
    <Modal
      open={open}
      onClose={close}
      title="Your AI tools on this machine"
      subtitle="SuperBased found these tools and is capturing the sessions they already have."
      icon={History}
      width={620}
      fullOnPhone
      footer={
        <>
          {data && !data.seen && (
            <Button variant="ghost" size="sm" onClick={dontShowAgain} className="mr-auto">
              Don't show this again
            </Button>
          )}
          <Button variant="secondary" size="sm" iconLeft={Plug} onClick={openTools}>
            Connected tools
          </Button>
          <Button variant="primary" size="sm" onClick={close}>
            {done ? "Done" : "Close"}
          </Button>
        </>
      }
    >
      <FirstRunBody view={view} onRetry={res.reload} retrying={res.isRefreshing} onOpenTools={openTools} />
    </Modal>
  );
}

/** FirstRunBody renders one of the five view states. Exported for screenshots. */
export function FirstRunBody({
  view,
  onRetry,
  retrying,
  onOpenTools,
}: {
  view: FirstRunView;
  onRetry: () => void;
  retrying?: boolean;
  onOpenTools: () => void;
}) {
  switch (view.kind) {
    case "loading":
      return (
        <div className="space-y-3" aria-busy="true" aria-label="Loading capture status">
          <Skeleton className="h-10" />
          <Skeleton className="h-16" />
          <Skeleton className="h-16" />
        </div>
      );
    case "error":
      return (
        <ErrorState
          variant="compact"
          title="Couldn't load capture status"
          error={view.message}
          onRetry={onRetry}
          retrying={retrying}
        />
      );
    case "empty":
      return (
        <EmptyState
          variant="inline"
          illustration="connect"
          illustrationSize={110}
          title="No AI coding tools found yet"
          body={
            view.watcherRunning
              ? "Install or open a supported tool, such as Claude Code, Codex or Cursor, and run it once. Its sessions show up here by themselves."
              : "The background watcher is not running here. Start SuperBased with observer start, then run one of your AI tools."
          }
        >
          <div className="mt-3 flex justify-center">
            <Button variant="secondary" size="sm" iconLeft={Plug} onClick={onOpenTools}>
              See supported tools
            </Button>
          </div>
        </EmptyState>
      );
    case "ready":
      return <ReadyBody view={view} onOpenTools={onOpenTools} />;
  }
}

function ReadyBody({
  view,
  onOpenTools,
}: {
  view: Extract<FirstRunView, { kind: "ready" }>;
  onOpenTools: () => void;
}) {
  const scanning = view.phase === "scanning" || view.phase === "idle";
  return (
    <div className="space-y-4">
      <section className="rounded-3 border border-line-2 bg-bg-2 p-3" aria-labelledby="sb-firstrun-status">
        <div className="flex items-start gap-2.5">
          <span className="mt-1 shrink-0">
            {scanning ? (
              <LiveDot tone="accent" label="Capture in progress" />
            ) : view.phase === "done" ? (
              <>
                <SuccessCheck size={16} />
                <span className="sr-only">Capture finished</span>
              </>
            ) : (
              <LiveDot tone={view.phase === "not_running" ? "warn" : "idle"} still label="Capture not running" />
            )}
          </span>
          <div className="min-w-0 flex-1">
            <p id="sb-firstrun-status" className="text-[13px] font-semibold text-fg-0" aria-live="polite">
              {view.headline}
            </p>
            <p className="mt-0.5 text-[11.5px] text-fg-3">{view.detail}</p>
          </div>
        </div>
        {(scanning || view.phase === "done") && (
          <div className="mt-3">
            {view.ratio == null ? (
              <Skeleton className="h-1.5 rounded-pill" />
            ) : (
              <Meter
                ratio={view.ratio}
                tone={view.phase === "done" ? "success" : "accent"}
                label="Share of past session files read"
              />
            )}
          </div>
        )}
      </section>

      <section aria-labelledby="sb-firstrun-tools">
        <h3 id="sb-firstrun-tools" className="mb-2 text-[12px] font-semibold text-fg-1">
          Tools found ({view.tools.length})
        </h3>
        <ul className="space-y-2">
          {view.tools.map((t) => (
            <ToolRow key={t.tool} t={t} />
          ))}
        </ul>
        {view.supportedNotFound > 0 && (
          <p className="mt-2 text-[11.5px] text-fg-3">
            {view.supportedNotFound} more supported tools were not found here.{" "}
            <button type="button" onClick={onOpenTools} className="text-accent hover:underline focus:outline-none focus-visible:underline">
              See the full list
            </button>
          </p>
        )}
      </section>

      {view.projects.length > 0 && (
        <section aria-labelledby="sb-firstrun-projects">
          <h3 id="sb-firstrun-projects" className="mb-2 text-[12px] font-semibold text-fg-1">
            Projects found ({view.projectCount})
          </h3>
          <ul className="grid gap-2 sm:grid-cols-2">
            {view.projects.map((p) => (
              <ProjectRow key={p.root} p={p} />
            ))}
          </ul>
          {view.projectCount > view.projects.length && (
            <p className="mt-2 text-[11.5px] text-fg-3">
              And {view.projectCount - view.projects.length} more on the Projects page.
            </p>
          )}
        </section>
      )}
    </div>
  );
}

function countLine(t: FirstRunTool): string {
  const s = `${t.sessions.toLocaleString("en-US")} session${t.sessions === 1 ? "" : "s"}`;
  if (t.projects <= 0) return s;
  return `${s}, ${t.projects.toLocaleString("en-US")} project${t.projects === 1 ? "" : "s"}`;
}

function ToolRow({ t }: { t: FirstRunTool }) {
  const badge = toolBadge(t);
  const h = t.history;
  const ratio = progressRatio(h.files_found, h.files_processed, h.files_failed);
  const moving = h.state === "scanning";
  return (
    <li className="rounded-3 border border-line-2 bg-bg-1 p-3">
      <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
        <ToolGlyphFrame tool={t.tool} size={20} />
        <span className="min-w-0 truncate text-[12.5px] font-semibold text-fg-0">{t.name}</span>
        <Pill variant={badge.tone} icon={moving ? LoaderCircle : undefined} spin={moving} case="none">
          {badge.label}
        </Pill>
        <span className="ml-auto text-[11px] tabular-nums text-fg-3">{countLine(t)}</span>
      </div>
      {moving && (
        <div className="mt-2 flex items-center gap-2">
          {ratio == null ? (
            <Skeleton className="h-1.5 flex-1 rounded-pill" />
          ) : (
            <Meter ratio={ratio} label={`Past session files read for ${t.name}`} className="flex-1" />
          )}
          <span className="shrink-0 text-[11px] tabular-nums text-fg-3">
            {h.files_found > 0 ? `${h.files_processed.toLocaleString("en-US")} of ${h.files_found.toLocaleString("en-US")} files` : "Looking for files"}
          </span>
        </div>
      )}
      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        {captureChips(t).map((c) => (
          <Pill key={c.key} variant={c.tone} title={c.title} case="none">
            {c.label}
          </Pill>
        ))}
      </div>
      {h.reason && h.state !== "scanning" && <p className="mt-1.5 text-[11px] text-fg-3">{h.reason}</p>}
      {t.detected_path && (
        <div className="mt-1.5 flex min-w-0 items-center gap-1 text-[10.5px] text-fg-4">
          <span className="shrink-0">Found at</span>
          <TruncatedPath value={t.detected_path} className="min-w-0 font-mono" />
        </div>
      )}
    </li>
  );
}

function ProjectRow({ p }: { p: FirstRunProject }) {
  return (
    <li className="flex min-w-0 items-center gap-2 rounded-2 border border-line-2 bg-bg-1 px-2.5 py-2">
      <Icon icon={FolderGit2} size="xs" className="shrink-0 text-fg-4" />
      <span className="min-w-0 flex-1">
        <span className="block truncate text-[12px] font-medium text-fg-1" title={p.root}>
          {p.name}
        </span>
        <span className="block text-[10.5px] tabular-nums text-fg-4">
          {p.sessions.toLocaleString("en-US")} session{p.sessions === 1 ? "" : "s"}
        </span>
      </span>
      {p.tools.length > 0 && <ToolStack tools={p.tools} max={3} size={16} />}
    </li>
  );
}
