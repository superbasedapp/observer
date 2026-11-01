import { Suspense, useEffect, useMemo, useState } from "react";
import { SANDBOX_SETTINGS_CARD } from "@/lib/components.gen";
import { useLocation, useNavigate } from "react-router-dom";
import { LayoutGrid, SlidersHorizontal, Swords, type LucideIcon } from "lucide-react";
import { useUrlTab } from "@/lib/useUrlTab";
import { usePageTabs } from "@/lib/governance";
import {
  TERMINALS_TABS,
  defaultTab,
  terminalsHashTab,
  type TerminalsTab,
} from "@/lib/nodePageTabs";
import {
  ChartShell,
  EmptyState,
  InlineLoading,
  PageHeader,
  Pill,
  SuccessCheck,
  TabPanel,
  TabStrip,
  panelDomId,
  tabDomId,
  type TabDef,
  Table,
  Tooltip,
} from "@/components/primitives";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable } from "@/components/DataTable";
import { navIcon } from "@/lib/nav";
import { useApi } from "@/lib/useApi";
import { fetchJSON } from "@/lib/api";
import { ConfigSaveCancelled, saveConfigEdit } from "@/lib/configSectionSave";
import { fmtClock, fmtRelative, fmtShortId } from "@/lib/format";
import type {
  ProjectRow,
  ProjectsResponse,
} from "@/lib/types";
import { markRestartPending } from "@/lib/restartPending";
import { unwatchedAllowedToolsMsg } from "@/lib/toolInstall";
import {
  useTerminalStatuses,
  AgentStatusBadge,
  type AgentStatusInfo,
} from "@/components/useTerminalStatuses";
import { WorkspaceGrid } from "@/components/workspace/WorkspaceGrid";
import { ArenaTab } from "@/components/arena/ArenaTab";
import { RemoteSystemsCard } from "@/components/RemoteSystemsCard";
import { FolderRootPicker, FolderSuggestions, rootsWithAdded, sortSuggestions } from "@/components/FolderSelection";
import { useHostOS } from "@/lib/keyPlatform";

async function postConfirmJSON<T>(
  path: string,
  confirmToken: string,
  body: unknown,
): Promise<T> {
  return fetchJSON<T>(path, undefined, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Observer-Confirm": confirmToken,
    },
    body: JSON.stringify(body ?? {}),
  });
}

// Terminals page (dashboard-management-surface plan §E). The settings sibling
// the cockpit F5 grid will later link into (this is the "Terminals" nav entry —
// deliberately not painted out). It surfaces three shipped things:
//   1. the [terminal.launch] launch-policy editor (allow_fresh_agent /
//      allowed_tools / allowed_project_roots) — a CapabilityLocal write, so it
//      only works from the local dashboard;
//   2. the live F4 agent-status stream (GET /ws/terminal/status);
//   3. the terminal_run history (GET /api/terminal/runs, metadata only).
// The launch policy EXPANDS execution authority, so the panel states that
// plainly and everything defaults off.

type TerminalPolicy = {
  confirm_token: string;
  config_writable: boolean;
  terminal_enabled: boolean;
  allow_fresh_agent: boolean;
  allowed_tools: string[];
  allowed_project_roots: string[];
  launchable_tools: string[];
  // allow_shell is a SEPARATE opt-in from allow_fresh_agent — a plain shell is
  // a strictly larger execution-authority expansion than a launchable AI tool
  // (arbitrary commands vs. one of the capability-registry's known
  // launchers), so it needs its own conscious toggle. See
  // internal/config's TerminalLaunchConfig.AllowShell.
  allow_shell: boolean;
  // [terminal.launch].allow_install: the guided install / uninstall switch
  // (default true; read live). Optional so an older daemon round-trips.
  allow_install?: boolean;
  restart_required_on_save: boolean;
  // Runtime bounds — live-applied by POST /api/terminal/limits (no restart),
  // read-only on this GET.
  max_concurrent: number;
  idle_timeout: string;
  // [observer.watch].enabled_adapters AS LOADED (audit DI-07) — the SECOND,
  // independent allow-list, which decides whether a launched tool is ever
  // CAPTURED. null/absent = the key is unset (every adapter watched); [] = the
  // explicit "watch nothing" intent. READ-ONLY here: it belongs to a different
  // config section and is NOT part of the PUT payload.
  enabled_adapters?: string[] | null;
  // The server-derived cross-check: allow-listed launchable tools an EXPLICIT
  // enabled_adapters list omits. They launch happily and record nothing.
  // Derived by diag.AllowedToolsNotWatched so the SPA never reimplements the
  // list's nil-vs-empty rule.
  unwatched_allowed_tools?: string[];
};

type RunRow = {
  run_id: string;
  tool: string;
  kind: string;
  launched_at: string;
  ended_at?: string;
  exit_code?: number;
  running: boolean;
  best_session_id?: string;
  best_confidence?: number;
  command_count: number;
};

// rootSeenHint renders a compact "N sessions · last seen …" suffix for a
// suggested project root. Purely cosmetic — the value is a hint, never a gate.
function rootSeenHint(p: ProjectRow): string {
  const sess = `${p.session_count} session${p.session_count === 1 ? "" : "s"}`;
  if (!p.last_seen) return sess;
  return `${sess} · last seen ${fmtRelative(p.last_seen)}`;
}

// putPolicy previews the launch-policy write and saves it at the previewed
// etag (REVIEW-3 P3-18), through the same dialog every config save uses. A
// cancelled preview rejects with ConfigSaveCancelled and writes nothing.
async function putPolicy(
  confirmToken: string,
  body: unknown,
): Promise<{ saved: boolean; restart_required: boolean }> {
  return saveConfigEdit(
    "/api/terminal/policy",
    "terminal.launch",
    body,
    { "X-Observer-Confirm": confirmToken },
    { title: "Save launch policy" },
  );
}

// The page's three views (`?tab=`, page tabs since the platform tabs plan),
// each with its own glyph, and the one-line description the header shows
// for the active view.
const TERMINALS_TAB_ICONS: Record<TerminalsTab, LucideIcon> = {
  workspace: LayoutGrid,
  settings: SlidersHorizontal,
  arena: Swords,
};
const TERMINALS_TAB_DEFS: TabDef<TerminalsTab>[] = TERMINALS_TABS.ids.map((id) => ({
  id,
  label: TERMINALS_TABS.labels[id],
  icon: TERMINALS_TAB_ICONS[id],
}));

const TERMINALS_TAB_SUBS: Record<TerminalsTab, string> = {
  workspace: "Your terminal workspace - run and arrange multiple live terminals on one grid.",
  arena:
    "Run one prompt against several agent harnesses in isolated worktrees, compare judged scorecards, keep the winner.",
  settings:
    "Launch policy, live agent status, and run history for the embedded terminal. Launch policy is an owner-local setting - it only saves from this machine.",
};

export function TerminalsPage() {
  const policy = useApi<TerminalPolicy>("/api/terminal/policy");
  const runs = useApi<{ runs: RunRow[] }>("/api/terminal/runs", undefined, [], {
    refreshMs: 15_000,
  });
  const statuses = useTerminalStatuses();

  const p = policy.data;
  const confirmToken = p?.confirm_token ?? "";
  // DI-07 cross-check, derived SERVER-side (unwatched_allowed_tools) and only
  // rendered here — null when there is no gap, or when the daemon predates the
  // key (absence is UNKNOWN, never "all watched").
  const unwatchedMsg = useMemo(
    () => unwatchedAllowedToolsMsg(p?.unwatched_allowed_tools),
    [p?.unwatched_allowed_tools],
  );

  // Workspace vs Settings tab (dock-grid design D1): the grid IS the page;
  // the policy/remote/standing/status/history content moves behind Settings.
  // `?tab=workspace|settings|arena` is the source of truth (useUrlTab: a
  // cold deep link renders that tab, a click pushes so Back walks tabs).
  // The provider's requestDock navigates to ?tab=workspace so a queued
  // "Add to grid" always lands on the grid, even if this page was left on
  // the Settings tab.
  // The tabs the organization left visible on this machine (T-132).
  const pageTabs = usePageTabs("terminals", TERMINALS_TABS);
  const [urlTab, setTab] = useUrlTab(pageTabs.ids, defaultTab(pageTabs));
  const location = useLocation();
  const navigate = useNavigate();
  // Hash deep-link: /terminals#launch-policy. The launch-policy card lives
  // behind the Settings tab, so a bare hash would land on the grid and scroll
  // to nothing: the hash selects its tab (in the URL, keeping the hash, as a
  // replace so Back does not bounce), then scrolls once the card has mounted.
  // The New-Terminal dialog's picker legend (DI-06) links here.
  const linkedTab = terminalsHashTab(location.hash);
  const hashTab = linkedTab && pageTabs.ids.includes(linkedTab) ? linkedTab : null;
  const tab: TerminalsTab = hashTab ?? urlTab;
  useEffect(() => {
    if (!hashTab) return;
    if (urlTab !== hashTab) {
      const next = new URLSearchParams(location.search);
      next.set("tab", hashTab);
      navigate({ search: `?${next.toString()}`, hash: location.hash }, { replace: true });
      return;
    }
    // The hash IS the card's element id (TERMINALS_SETTINGS_ANCHORS):
    // #launch-policy, #folder-selection, #remote-systems.
    const id = window.setTimeout(() => {
      document
        .getElementById(location.hash.slice(1))
        ?.scrollIntoView({ block: "start", behavior: "smooth" });
    }, 0);
    return () => window.clearTimeout(id);
  }, [hashTab, urlTab, location.search, location.hash, navigate]);

  // Local editable copy of the policy, seeded from the server.
  const [allowFresh, setAllowFresh] = useState(false);
  const [allowShell, setAllowShell] = useState(false);
  const [allowInstall, setAllowInstall] = useState(true);
  const [tools, setTools] = useState<string[]>([]);
  const [roots, setRoots] = useState<string[]>([]);
  const [newRoot, setNewRoot] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  // Known project roots (GET /api/projects) power the add-able suggestion list
  // below the free-text input. These are OBSERVED, tool-reported roots — pure
  // SUGGESTIONS; the operator explicitly allow-lists one by adding + saving,
  // and the server re-validates every entry on save (a stale/foreign/symlink-
  // mismatched root is rejected there, not here).
  const [projects, setProjects] = useState<ProjectRow[]>([]);

  // Runtime-bounds editor state (POST /api/terminal/limits — live-applied).
  // max_concurrent is kept as a string so the input can be transiently empty;
  // idle_timeout is a free-text Go duration ("0" = never).
  const [maxConcurrent, setMaxConcurrent] = useState("");
  const [idleTimeout, setIdleTimeout] = useState("");
  const [limitsBusy, setLimitsBusy] = useState(false);
  const [limitsErr, setLimitsErr] = useState<string | null>(null);
  const [limitsMsg, setLimitsMsg] = useState<string | null>(null);

  useEffect(() => {
    if (p) {
      setAllowFresh(p.allow_fresh_agent);
      setAllowShell(p.allow_shell);
      setAllowInstall(p.allow_install ?? true);
      setTools(p.allowed_tools ?? []);
      setRoots(p.allowed_project_roots ?? []);
      setMaxConcurrent(String(p.max_concurrent ?? 0));
      setIdleTimeout(p.idle_timeout ?? "");
    }
  }, [p]);

  useEffect(() => {
    let cancelled = false;
    fetchJSON<ProjectsResponse>("/api/projects")
      .then((d) => {
        if (!cancelled) setProjects(d.rows ?? []);
      })
      .catch(() => {
        /* no project index yet — the free-text input is the fallback */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Suggestions = observed project roots, the node's native ones first (a
  // root this node's OS does not use will be rejected server-side, so it is
  // de-prioritized cosmetically but still offered). The OS is the daemon's
  // own (/api/status.host_os), never a guess (RERUN2 D5c). Already-added
  // roots stay in the list, shown as added.
  const hostOS = useHostOS();
  const rootSuggestions = useMemo(() => sortSuggestions(projects, hostOS), [projects, hostOS]);

  const statusList = useMemo(() => Object.values(statuses), [statuses]);
  const liveStatuses = statusList.filter((s) => s.status !== "exited");

  function toggleTool(tool: string) {
    setSaved(false);
    setTools((cur) =>
      cur.includes(tool) ? cur.filter((t) => t !== tool) : [...cur, tool],
    );
  }

  function addRootValue(raw: string) {
    const r = raw.trim();
    if (!r) return;
    setSaved(false);
    setRoots((cur) => rootsWithAdded(cur, r));
  }

  function addRoot() {
    addRootValue(newRoot);
    setNewRoot("");
  }

  async function save() {
    if (!confirmToken) {
      setErr("No confirm token - reload the page.");
      return;
    }
    setBusy(true);
    setErr(null);
    setSaved(false);
    try {
      const res = await putPolicy(confirmToken, {
        allow_fresh_agent: allowFresh,
        allowed_tools: tools,
        allowed_project_roots: roots,
        allow_shell: allowShell,
        allow_install: allowInstall,
      });
      if (res.restart_required) markRestartPending("terminal-policy");
      setSaved(true);
      policy.reload();
    } catch (e) {
      if (!(e instanceof ConfigSaveCancelled)) setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function saveLimits() {
    if (!confirmToken) {
      setLimitsErr("No confirm token - reload the page.");
      return;
    }
    // Client-side sanity only: a non-negative integer. The server owns
    // duration validation and surfaces its own message.
    const trimmed = maxConcurrent.trim();
    const n = Number(trimmed);
    if (trimmed === "" || !Number.isInteger(n) || n < 0) {
      setLimitsErr("Max concurrent must be a non-negative whole number.");
      return;
    }
    setLimitsBusy(true);
    setLimitsErr(null);
    setLimitsMsg(null);
    // Send only the fields that changed from the loaded policy.
    const body: { max_concurrent?: number; idle_timeout?: string } = {};
    if (n !== (p?.max_concurrent ?? 0)) body.max_concurrent = n;
    if (idleTimeout.trim() !== (p?.idle_timeout ?? "")) {
      body.idle_timeout = idleTimeout.trim();
    }
    if (body.max_concurrent === undefined && body.idle_timeout === undefined) {
      setLimitsMsg("No changes.");
      setLimitsBusy(false);
      return;
    }
    try {
      const res = await postConfirmJSON<{ restart_required: boolean }>(
        "/api/terminal/limits",
        confirmToken,
        body,
      );
      setLimitsMsg(
        res.restart_required ? "Saved - restart required." : "Applied live.",
      );
      policy.reload();
    } catch (e) {
      setLimitsErr(e instanceof Error ? e.message : String(e));
    } finally {
      setLimitsBusy(false);
    }
  }

  return (
    <div className="p-4 sm:p-6">
      <PageHeader
        className="mb-4"
        title="Terminals"
        icon={navIcon("terminals")}
        sub={TERMINALS_TAB_SUBS[tab]}
      />

      <TabStrip
        tabs={TERMINALS_TAB_DEFS.filter((t) => pageTabs.ids.includes(t.id))}
        value={tab}
        onChange={setTab}
        idPrefix="terminals"
        ariaLabel="Terminals sections"
        className="mb-4"
      />

      {/* The grid mounts only while its tab is shown (as before the tab
          strip): live xterms and the grid layout measure their box, which a
          display:none keep-alive panel would report as zero. */}
      {tab === "workspace" && (
        <div
          id={panelDomId("terminals", "workspace")}
          role="tabpanel"
          aria-labelledby={tabDomId("terminals", "workspace")}
        >
          <WorkspaceGrid
            policyHint={
              p && (!p.terminal_enabled || !p.allow_fresh_agent)
                ? "Fresh launch is off - enable it in Settings → Fresh-agent launch policy."
                : ""
            }
            onOpenSettings={() => setTab("settings")}
          />
        </div>
      )}

      <TabPanel id="arena" active={tab} idPrefix="terminals">
        <ArenaTab />
      </TabPanel>

      <TabPanel id="settings" active={tab} idPrefix="terminals" className="space-y-6">
        <>

      {/* Launch policy editor (§E). The id is the deep-link target the
          New-Terminal dialog's picker legend points at (/terminals#launch-policy,
          audit DI-06); scroll-mt keeps the card clear of the sticky header. */}
      <div id="launch-policy" className="scroll-mt-6">
      <ChartShell
        title="Fresh-agent launch policy"
        sub="Controls whether the dashboard may start a NEW agent (not just continue an existing session) in the embedded terminal. This expands execution authority - everything defaults off."
        right={
          <div className="flex flex-wrap items-center gap-1.5">
            <Pill variant={p?.allow_fresh_agent ? "warn" : "neutral"}>
              {p?.allow_fresh_agent ? "fresh launch on" : "fresh launch off"}
            </Pill>
            {/* DI-07: the SECOND allow-list. A tool can be allow-listed for
                launch and still be omitted from [observer.watch].enabled_adapters
                — it launches fine and records nothing, which is exactly the kind
                of silent failure that looks like a capture bug. Read-only: the
                key lives in a different config section and is NOT in the PUT. */}
            {unwatchedMsg && (
              <Pill variant="warn" title={unwatchedMsg}>
                {(p?.unwatched_allowed_tools ?? []).length} not watched
              </Pill>
            )}
          </div>
        }
      >
        <div className="space-y-4 p-1 text-[12px]">
          {unwatchedMsg && (
            <div className="rounded-2 border border-warn/40 bg-warn/10 px-3 py-2 text-warn">
              {unwatchedMsg}
            </div>
          )}
          {!p?.config_writable && (
            <div className="rounded-2 border border-line-2 bg-bg-2 px-3 py-2 text-fg-3">
              This dashboard was started without a writable config path, so launch policy can't be edited
              here. Edit <code className="text-fg-2">[terminal.launch]</code> in your config.toml instead.
            </div>
          )}
          {p?.terminal_enabled === false && (
            <div className="rounded-2 border border-warn/40 bg-warn/10 px-3 py-2 text-warn">
              The terminal surface is disabled ([terminal].enabled = false). Fresh launch needs both it and
              the master toggle below.
            </div>
          )}

          <label className="flex items-start gap-2">
            <input
              type="checkbox"
              checked={allowFresh}
              disabled={!p?.config_writable}
              onChange={(e) => {
                setSaved(false);
                setAllowFresh(e.target.checked);
              }}
              className="mt-0.5"
            />
            <span>
              <span className="font-medium text-fg-1">Allow fresh-agent launches</span>
              <span className="block text-[11px] text-fg-3">
                When on, the dashboard can spawn a new agent from the launchable set below, in one of the
                allowed project roots. When off, every fresh-launch request is refused (session continuation
                is unaffected).
              </span>
            </span>
          </label>

          <label className="flex items-start gap-2">
            <input
              type="checkbox"
              checked={allowShell}
              disabled={!p?.config_writable}
              onChange={(e) => {
                setSaved(false);
                setAllowShell(e.target.checked);
              }}
              className="mt-0.5"
            />
            <span>
              <span className="font-medium text-fg-1">Allow plain shell terminals</span>
              <span className="block text-[11px] text-fg-3">
                A SEPARATE opt-in from fresh-agent launches above - it starts your own shell ($SHELL, or
                bash/sh as a fallback) instead of an AI tool, so it is a strictly larger execution-authority
                expansion (any command, not one of the launchable tools). Turning on fresh-agent launches
                does not also grant this. Config key: <code className="text-fg-2">[terminal.launch].allow_shell</code>.
              </span>
            </span>
          </label>

          <label className="flex items-start gap-2">
            <input
              type="checkbox"
              checked={allowInstall}
              disabled={!p?.config_writable}
              onChange={(e) => {
                setSaved(false);
                setAllowInstall(e.target.checked);
              }}
              className="mt-0.5"
            />
            <span>
              <span className="font-medium text-fg-1">Allow guided install and uninstall</span>
              <span className="block text-[11px] text-fg-3">
                Lets New Terminal run a tool&apos;s grounded install (or the uninstall of one this dashboard
                installed) in a local terminal. On by default; installing is not launching, so the launch
                allow-list above does not gate it. Config key:{" "}
                <code className="text-fg-2">[terminal.launch].allow_install</code>.
              </span>
            </span>
          </label>

          <div>
            <div className="mb-1 text-[11px] text-fg-3">
              allowed tools (from the launchable set - a tool must be launchable in the capability registry)
            </div>
            <div className="flex flex-wrap gap-1.5">
              {(p?.launchable_tools ?? []).map((tool) => {
                const on = tools.includes(tool);
                return (
                  <button
                    key={tool}
                    type="button"
                    disabled={!p?.config_writable}
                    onClick={() => toggleTool(tool)}
                    className={`rounded-2 border px-2 py-0.5 text-[11px] disabled:opacity-40 ${
                      on
                        ? "border-accent/50 bg-accent/15 text-accent"
                        : "border-line-2 bg-bg-2 text-fg-3 hover:bg-bg-3"
                    }`}
                  >
                    {tool}
                  </button>
                );
              })}
            </div>
            {tools.length === 0 && (
              <div className="mt-1 text-[11px] text-fg-3">
                None selected - no tool may fresh-launch (deny-all).
              </div>
            )}
          </div>

          {/* Save error surfaced inline - the server rejects the WHOLE write on
              any bad entry (incl. a rejected project root) with a message
              naming which field/entry, so the operator can fix it here or in
              the Folder Selection card below (same shared state + save()). */}
          {err && (
            <div className="rounded-2 border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger">
              {err}
            </div>
          )}

          <div className="flex items-center gap-3 pt-1">
            <button
              type="button"
              disabled={busy || !p?.config_writable}
              onClick={save}
              className="rounded-2 border border-accent/50 bg-accent/15 px-3 py-1 text-[12px] text-accent hover:bg-accent/25 disabled:opacity-50"
            >
              {busy ? "saving…" : "Save launch policy"}
            </button>
            {saved && <SuccessCheck label="Saved" className="!text-[11px]" />}
            <LaunchPolicyBindNote restartRequired={p?.restart_required_on_save} />
          </div>
        </div>
      </ChartShell>
      </div>

      {/* Folder Selection (bug 4b): the allow-list management surface for
          [terminal.launch].allowed_project_roots, split out of the launch-
          policy card above into its own section since it's a distinct
          concern (WHERE an agent may run vs. WHETHER/WHICH one may). It is
          wired to the exact same `roots`/`newRoot`/`rootSuggestions` state
          and `addRoot`/`addRootValue`/`save` handlers as the card above -
          Save here submits the FULL policy (allow_fresh_agent + allowed_tools
          + allowed_project_roots + allow_shell), never a roots-only payload,
          because the PUT handler (handleTerminalPolicyPut) overwrites all
          four fields unconditionally from the request body. A partial write
          from here would silently reset fresh-launch/tools/shell back off. */}
      <div id="folder-selection" className="scroll-mt-6">
      <ChartShell
        title="Folder Selection"
        sub="The allow-list of project folders a fresh agent (or plain shell) may be launched into - from here, or from the folder picker in New Terminal. A folder's descendants are permitted too (adding /home/you/work also allow-lists /home/you/work/anything-under-it); the server re-canonicalizes and symlink-checks every entry on save."
        right={
          <Pill variant={roots.length === 0 ? "neutral" : "success"}>
            {roots.length === 0 ? "no folders allowed" : `${roots.length} folder${roots.length === 1 ? "" : "s"} allowed`}
          </Pill>
        }
      >
        <div className="space-y-4 p-1 text-[12px]">
          {!p?.config_writable && (
            <div className="rounded-2 border border-line-2 bg-bg-2 px-3 py-2 text-fg-3">
              This dashboard was started without a writable config path, so the allow-list can't be edited
              here. Edit <code className="text-fg-2">[terminal.launch].allowed_project_roots</code> in your
              config.toml instead.
            </div>
          )}

          <div>
            <div className="mb-1 text-[11px] text-fg-3">
              allowed project roots (each is canonicalized + symlink-checked on save; must be an existing
              absolute directory)
            </div>
            <div className="space-y-1">
              {roots.map((r) => (
                <div key={r} className="flex items-center gap-2">
                  <code className="flex-1 break-all rounded-2 border border-line-2 bg-bg-3 px-2 py-1 font-mono text-[11px] text-fg-2">
                    {r}
                  </code>
                  <button
                    type="button"
                    disabled={!p?.config_writable}
                    onClick={() => {
                      setSaved(false);
                      setRoots((cur) => cur.filter((x) => x !== r));
                    }}
                    className="rounded-2 border border-line-2 bg-bg-2 px-2 py-1 text-[11px] text-fg-3 hover:bg-bg-3 disabled:opacity-40"
                  >
                    remove
                  </button>
                </div>
              ))}
              {roots.length === 0 && (
                <div className="text-[11px] text-fg-3">
                  None - no project_root may be set. A fresh launch with no project root runs in the SuperBased
                  daemon's own working directory (the directory <code className="text-fg-2">observer start</code> /{" "}
                  <code className="text-fg-2">observer dashboard</code> was launched from).
                </div>
              )}
              <div className="flex items-center gap-2 pt-1">
                {/* D-571: pick an observed project (or type another absolute
                    path); "add" puts the pick on the list. */}
                <FolderRootPicker
                  suggestions={rootSuggestions}
                  roots={roots}
                  value={newRoot}
                  disabled={!p?.config_writable}
                  onChange={setNewRoot}
                  hostOS={hostOS}
                  seenHint={rootSeenHint}
                />
                <button
                  type="button"
                  disabled={!p?.config_writable || newRoot.trim() === ""}
                  onClick={addRoot}
                  className="rounded-2 border border-line-2 bg-bg-2 px-2 py-1 text-[11px] text-fg-2 hover:bg-bg-3 disabled:opacity-40"
                >
                  add
                </button>
              </div>
            </div>

            {/* Add-able suggestions from observed projects (GET /api/projects):
                pure SUGGESTIONS, each added only by its own click
                (components/FolderSelection.tsx, OS-aware from the node's
                reported OS). The server re-validates every entry on save. */}
            <FolderSuggestions
              suggestions={rootSuggestions}
              roots={roots}
              hostOS={hostOS}
              writable={!!p?.config_writable}
              onAdd={addRootValue}
              seenHint={rootSeenHint}
            />
          </div>

          {err && (
            <div className="rounded-2 border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger">
              {err}
            </div>
          )}

          <div className="flex items-center gap-3 pt-1">
            <button
              type="button"
              disabled={busy || !p?.config_writable}
              onClick={save}
              className="rounded-2 border border-accent/50 bg-accent/15 px-3 py-1 text-[12px] text-accent hover:bg-accent/25 disabled:opacity-50"
            >
              {busy ? "saving…" : "Save folder allow-list"}
            </button>
            {saved && <SuccessCheck label="Saved" className="!text-[11px]" />}
            <LaunchPolicyBindNote restartRequired={p?.restart_required_on_save} />
          </div>
        </div>
      </ChartShell>
      </div>

      {/* Remote systems (T-488): the [[terminal.ssh.profiles]] editor the
          New Terminal System picker links to (/terminals#remote-systems). */}
      <RemoteSystemsCard />

      {/* The Sandboxes and VMs module's Card, a compgen feature row: null in a
          build without the module, so the page renders no sandbox element. */}
      {SANDBOX_SETTINGS_CARD && (
        <Suspense fallback={null}>
          <SANDBOX_SETTINGS_CARD />
        </Suspense>
      )}

      {/* Terminal limits — the two runtime bounds live-applied to the PTY
          manager (POST /api/terminal/limits). Unlike the launch policy above,
          these bind immediately (no restart). Owner-local write. */}
      <ChartShell
        title="Terminal limits"
        sub="How many terminals can run at once, and when to reap idle ones. Applied live - no restart."
      >
        <div className="space-y-3">
          <div className="flex flex-col gap-1">
            <label className="text-[12px] font-medium text-fg-1">
              Max concurrent terminals
            </label>
            <input
              type="number"
              min={0}
              step={1}
              value={maxConcurrent}
              disabled={!p?.config_writable}
              onChange={(e) => setMaxConcurrent(e.target.value)}
              className="w-32 rounded-2 border border-line-2 bg-bg-3 px-2 py-1 text-[12px] text-fg-1 disabled:opacity-50"
            />
            <p className="text-[11px] text-fg-3">
              How many embedded/attach terminals can run at once. The Workspace
              grid is sized for 9.
            </p>
          </div>

          <div className="flex flex-col gap-1">
            <label className="text-[12px] font-medium text-fg-1">
              Idle timeout
            </label>
            <input
              type="text"
              value={idleTimeout}
              placeholder="0"
              disabled={!p?.config_writable}
              onChange={(e) => setIdleTimeout(e.target.value)}
              className="w-32 rounded-2 border border-line-2 bg-bg-3 px-2 py-1 text-[12px] text-fg-1 disabled:opacity-50"
            />
            <p className="text-[11px] text-fg-3">
              0 = never (default): live sessions stay until the agent exits. Set
              a Go duration (e.g. 30m, 2h) to reap terminals with no I/O for that
              long.
            </p>
          </div>

          {limitsErr && (
            <div className="rounded-2 border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger">
              {limitsErr}
            </div>
          )}

          <div className="flex items-center gap-3 pt-1">
            <button
              type="button"
              disabled={limitsBusy || !p?.config_writable}
              onClick={saveLimits}
              className="rounded-2 border border-accent/50 bg-accent/15 px-3 py-1 text-[12px] text-accent hover:bg-accent/25 disabled:opacity-50"
            >
              {limitsBusy ? "saving…" : "Save limits"}
            </button>
            {limitsMsg && <SuccessCheck label={limitsMsg} className="!text-[11px]" />}
          </div>
        </div>
      </ChartShell>

      {/* Live F4 agent status. */}
      <ChartShell
        title="Live agent status"
        sub="Fused from PTY activity, OSC hints, and launcher lifecycle (F4). Low-confidence hints are shown muted - a hint is never presented as certainty."
      >
        <div className="p-1 text-[12px]">
          {liveStatuses.length === 0 ? (
            <EmptyState
              variant="inline"
              illustration="sessions"
              illustrationSize={96}
              title="No live terminal agents"
              body="Launch a terminal from New Terminal and its agent status appears here."
            />
          ) : (
            <DataTable<AgentStatusInfo>
              data={liveStatuses}
              columns={LIVE_STATUS_COLUMNS}
              rowKey={(st) => st.handle}
              minWidth={480}
            />
          )}
        </div>
      </ChartShell>

      {/* Run history. */}
      <ChartShell
        title="Run history"
        sub="Every dashboard terminal launch (metadata only - project roots and correlation tokens are stored hashed, never in the clear). Correlated session appears once the launch produces one."
      >
        <div className="p-1 text-[11px]">
          {runs.loading && !runs.data ? (
            <InlineLoading label="Loading run history" block />
          ) : (runs.data?.runs.length ?? 0) === 0 ? (
            <EmptyState
              variant="inline"
              illustration="sessions"
              illustrationSize={96}
              title="No terminal runs yet"
            />
          ) : (
            <Table
              maxHeight={320}
              stickyHead
              size="sm"
              minWidth={520}
              tableClassName="font-mono"
              head={
                <tr>
                  <th className="py-1 pr-2 font-medium">Launched</th>
                  <th className="py-1 pr-2 font-medium">Tool</th>
                  <th className="py-1 pr-2 font-medium">Kind</th>
                  <th className="py-1 pr-2 font-medium">State</th>
                  <th className="py-1 pr-2 font-medium">Session</th>
                  <th className="py-1 font-medium">Cmds</th>
                </tr>
              }
            >
              {runs.data?.runs.map((r) => (
                <tr key={r.run_id} className="border-t border-line-1 text-fg-2">
                  <td className="whitespace-nowrap py-1 pr-2">{fmtClock(r.launched_at)}</td>
                  <td className="py-1 pr-2">{r.tool}</td>
                  <td className="py-1 pr-2">{r.kind}</td>
                  <td className="py-1 pr-2">
                    {r.running ? (
                      <Pill variant="success">running</Pill>
                    ) : r.exit_code === 0 || r.exit_code === undefined ? (
                      <span className="text-fg-3">exited</span>
                    ) : (
                      <Pill variant="danger">exit {r.exit_code}</Pill>
                    )}
                  </td>
                  <td className="py-1 pr-2">
                    {r.best_session_id ? (
                      <Tooltip content={`${r.best_session_id} · confidence ${(r.best_confidence ?? 0).toFixed(2)}`}>
                        <span
                          tabIndex={0}
                          className="cursor-help focus:outline-none focus-visible:ring-1 focus-visible:ring-accent-ring"
                        >
                          {fmtShortId(r.best_session_id, 10)}
                        </span>
                      </Tooltip>
                    ) : (
                      <span className="text-fg-3">-</span>
                    )}
                  </td>
                  <td className="py-1">{r.command_count}</td>
                </tr>
              ))}
            </Table>
          )}
        </div>
      </ChartShell>
        </>
      </TabPanel>
    </div>
  );
}

// LaunchPolicyBindNote says when a launch-policy save takes effect. A daemon
// that reads [terminal.launch] live (T-489) binds it on the next launch; an
// older one, or an embedder without the live seam, still needs a restart, and
// the note says whichever the daemon reported.
function LaunchPolicyBindNote({ restartRequired }: { restartRequired?: boolean }) {
  if (restartRequired === undefined) return null;
  return (
    <span className="text-[11px] text-fg-3">
      {restartRequired
        ? "Takes effect on the next daemon restart (this daemon reads the policy at start-up)."
        : "Applies to the next launch - no restart needed."}
    </span>
  );
}

// LIVE_STATUS_COLUMNS: the live agent list (F4 statuses). Status and age
// sort; the handle is an opaque id.
const LIVE_STATUS_COLUMNS: ColumnDef<AgentStatusInfo, unknown>[] = [
  {
    id: "handle",
    header: "Handle",
    enableSorting: false,
    meta: { mono: true },
    cell: ({ row }) => (
      <span title={row.original.handle}>{fmtShortId(row.original.handle, 12)}</span>
    ),
  },
  {
    id: "status",
    header: "Status",
    accessorKey: "status",
    cell: ({ row }) => <AgentStatusBadge info={row.original} />,
  },
  {
    id: "evidence",
    header: "Evidence",
    enableSorting: false,
    cell: ({ row }) => <span className="text-fg-3">{row.original.evidence}</span>,
  },
  {
    id: "age",
    header: "Age",
    accessorFn: (st) => st.age_seconds,
    meta: { align: "right", mono: true },
    cell: ({ row }) => `${Math.round(row.original.age_seconds)}s`,
  },
];
