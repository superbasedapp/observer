import { useEffect, useMemo, useState } from "react";
import { useLocation } from "react-router-dom";
import { ChartShell, Pill } from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import { fetchJSON } from "@/lib/api";
import { fmtClock, fmtRelative, fmtShortId } from "@/lib/format";
import type {
  ProjectRow,
  ProjectsResponse,
  SandboxAvailability,
} from "@/lib/types";
import { markRestartPending } from "@/lib/restartPending";
import { unwatchedAllowedToolsMsg } from "@/lib/toolInstall";
import {
  useTerminalStatuses,
  AgentStatusBadge,
} from "@/components/useTerminalStatuses";
import { WorkspaceGrid } from "@/components/workspace/WorkspaceGrid";
import { ArenaTab } from "@/components/arena/ArenaTab";

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

// shortenPath renders an absolute root as ".../parent/leaf" for compact display
// (the full path rides along as a title tooltip). Mirrors the NewTerminalDialog
// project-picker convention so the two surfaces read the same.
function shortenPath(p: string): string {
  if (!p) return "-";
  const parts = p.split("/").filter(Boolean);
  if (parts.length <= 2) return p;
  return ".../" + parts.slice(-2).join("/");
}

// rootSeenHint renders a compact "N sessions · last seen …" suffix for a
// suggested project root. Purely cosmetic — the value is a hint, never a gate.
function rootSeenHint(p: ProjectRow): string {
  const sess = `${p.session_count} session${p.session_count === 1 ? "" : "s"}`;
  if (!p.last_seen) return sess;
  return `${sess} · last seen ${fmtRelative(p.last_seen)}`;
}

async function putPolicy(
  confirmToken: string,
  body: unknown,
): Promise<{ saved: boolean; restart_required: boolean }> {
  return fetchJSON("/api/terminal/policy", undefined, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      "X-Observer-Confirm": confirmToken,
    },
    body: JSON.stringify(body),
  });
}

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
  const [tab, setTab] = useState<"workspace" | "settings" | "arena">("workspace");
  // Deep-link: /terminals?tab=workspace|settings (the provider's requestDock
  // navigates here so a queued "Add to grid" always lands on the grid, even
  // if this page was left on the Settings tab).
  const location = useLocation();
  useEffect(() => {
    const want = new URLSearchParams(location.search).get("tab");
    if (want === "workspace" || want === "settings" || want === "arena") setTab(want);
  }, [location.search]);
  // Hash deep-link: /terminals#launch-policy. The launch-policy card lives
  // behind the Settings tab, so a bare hash would land on the grid and scroll
  // to nothing — select the tab FIRST, then scroll once the card has mounted.
  // The New-Terminal dialog's picker legend (DI-06) links here.
  useEffect(() => {
    if (location.hash !== "#launch-policy") return;
    setTab("settings");
    const id = window.setTimeout(() => {
      document
        .getElementById("launch-policy")
        ?.scrollIntoView({ block: "start", behavior: "smooth" });
    }, 0);
    return () => window.clearTimeout(id);
  }, [location.hash]);

  // Local editable copy of the policy, seeded from the server.
  const [allowFresh, setAllowFresh] = useState(false);
  const [allowShell, setAllowShell] = useState(false);
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

  // Suggestions = observed project roots, POSIX-absolute ones first (a foreign/
  // Windows root will be rejected server-side, so it's de-prioritized cosmetically
  // but still offered). Already-added roots stay in the list, shown as added.
  const rootSuggestions = useMemo(() => {
    return [...projects].sort((a, b) => {
      const af = a.root_path.startsWith("/") ? 0 : 1;
      const bf = b.root_path.startsWith("/") ? 0 : 1;
      return af - bf;
    });
  }, [projects]);

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
    setRoots((cur) => (cur.includes(r) ? cur : [...cur, r]));
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
      });
      if (res.restart_required) markRestartPending("terminal-policy");
      setSaved(true);
      policy.reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
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
    <div className="space-y-4 p-5">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h1 className="text-[15px] font-semibold text-fg-1">Terminals</h1>
          <p className="mt-0.5 text-[12px] text-fg-3">
            {tab === "workspace"
              ? "Your terminal workspace - run and arrange multiple live terminals on one grid."
              : tab === "arena"
                ? "Run one prompt against several agent harnesses in isolated worktrees, compare judged scorecards, keep the winner."
                : "Launch policy, live agent status, and run history for the embedded terminal. Launch policy is an owner-local setting - it only saves from this machine."}
          </p>
        </div>
        <div className="flex gap-1 rounded-2 border border-line-2 bg-bg-1 p-0.5 text-[12px]">
          <button
            type="button"
            onClick={() => setTab("workspace")}
            className={
              tab === "workspace"
                ? "rounded-[6px] bg-bg-3 px-3 py-1 text-fg-1"
                : "rounded-[6px] px-3 py-1 text-fg-3 hover:text-fg-1"
            }
          >
            Workspace
          </button>
          <button
            type="button"
            onClick={() => setTab("settings")}
            className={
              tab === "settings"
                ? "rounded-[6px] bg-bg-3 px-3 py-1 text-fg-1"
                : "rounded-[6px] px-3 py-1 text-fg-3 hover:text-fg-1"
            }
          >
            Settings
          </button>
          <button
            type="button"
            onClick={() => setTab("arena")}
            className={
              tab === "arena"
                ? "rounded-[6px] bg-bg-3 px-3 py-1 text-fg-1"
                : "rounded-[6px] px-3 py-1 text-fg-3 hover:text-fg-1"
            }
          >
            Arena
          </button>
        </div>
      </div>

      {tab === "workspace" && (
        <WorkspaceGrid
          policyHint={
            p && (!p.terminal_enabled || !p.allow_fresh_agent)
              ? "Fresh launch is off - enable it in Settings → Fresh-agent launch policy."
              : ""
          }
          onOpenSettings={() => setTab("settings")}
        />
      )}

      {tab === "arena" && <ArenaTab />}

      {tab === "settings" && (
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
            {saved && <span className="text-[11px] text-ok">Saved.</span>}
            {p?.restart_required_on_save && (
              <span className="text-[11px] text-fg-3">
                Takes effect on the next daemon restart (the policy is read at start-up).
              </span>
            )}
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
                  <code className="flex-1 break-all rounded-2 border border-line-2 bg-bg-1 px-2 py-1 font-mono text-[11px] text-fg-2">
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
                <input
                  value={newRoot}
                  disabled={!p?.config_writable}
                  onChange={(e) => setNewRoot(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") addRoot();
                  }}
                  placeholder="/absolute/path/to/project"
                  className="flex-1 rounded-2 border border-line-2 bg-bg-1 px-2 py-1 font-mono text-[11px] text-fg-1 outline-none focus:border-accent disabled:opacity-40"
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

            {/* Add-able suggestions from observed projects (GET /api/projects).
                These are pure SUGGESTIONS — the operator allow-lists a root by
                adding it and saving; the server re-validates every entry on save
                and rejects stale/foreign/symlink-mismatched ones with a reason
                (surfaced inline near Save below). */}
            {rootSuggestions.length > 0 && (
              <div className="mt-3 rounded-2 border border-line-1 bg-bg-1 p-2">
                <div className="mb-1.5 text-[11px] text-fg-3">
                  Suggested from observed projects - add one to allow-list it. Roots are validated on save; a
                  foreign (Windows/UNC), stale, or symlink-mismatched root is rejected there, not here.
                </div>
                <div className="max-h-[220px] space-y-1 overflow-auto">
                  {rootSuggestions.map((proj) => {
                    const added = roots.includes(proj.root_path);
                    const foreign = !proj.root_path.startsWith("/");
                    return (
                      <div key={proj.root_path} className="flex items-center gap-2">
                        <code
                          title={proj.root_path}
                          className={`min-w-0 flex-1 truncate rounded-2 border border-line-2 bg-bg-0 px-2 py-1 font-mono text-[11px] ${
                            foreign ? "text-fg-3" : "text-fg-2"
                          }`}
                        >
                          {shortenPath(proj.root_path)}
                        </code>
                        <span className="hidden whitespace-nowrap text-[10px] text-fg-3 sm:inline">
                          {rootSeenHint(proj)}
                        </span>
                        <button
                          type="button"
                          disabled={!p?.config_writable || added}
                          title={
                            foreign
                              ? `${proj.root_path} - looks like a foreign path; it will likely be rejected on save`
                              : proj.root_path
                          }
                          onClick={() => addRootValue(proj.root_path)}
                          className={`shrink-0 rounded-2 border px-2 py-1 text-[11px] disabled:opacity-40 ${
                            added
                              ? "border-line-2 bg-bg-2 text-fg-3"
                              : "border-accent/50 bg-accent/15 text-accent hover:bg-accent/25"
                          }`}
                        >
                          {added ? "added" : "add"}
                        </button>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
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
            {saved && <span className="text-[11px] text-ok">Saved.</span>}
            {p?.restart_required_on_save && (
              <span className="text-[11px] text-fg-3">
                Takes effect on the next daemon restart (the policy is read at start-up).
              </span>
            )}
          </div>
        </div>
      </ChartShell>

      <SandboxSettingsCard />

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
              className="w-32 rounded-2 border border-line-2 bg-bg-1 px-2 py-1 text-[12px] text-fg-1 disabled:opacity-50"
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
              className="w-32 rounded-2 border border-line-2 bg-bg-1 px-2 py-1 text-[12px] text-fg-1 disabled:opacity-50"
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
            {limitsMsg && <span className="text-[11px] text-ok">{limitsMsg}</span>}
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
            <div className="text-fg-3">No live terminal agents.</div>
          ) : (
            <table className="w-full text-left">
              <thead className="text-[11px] text-fg-3">
                <tr>
                  <th className="py-1">handle</th>
                  <th className="py-1">status</th>
                  <th className="py-1">evidence</th>
                  <th className="py-1">age</th>
                </tr>
              </thead>
              <tbody className="font-mono text-fg-2">
                {liveStatuses.map((st) => (
                  <tr key={st.handle} className="border-t border-line-1">
                    <td className="py-1" title={st.handle}>{fmtShortId(st.handle, 12)}</td>
                    <td className="py-1">
                      <AgentStatusBadge info={st} />
                    </td>
                    <td className="py-1 font-sans text-fg-3">{st.evidence}</td>
                    <td className="py-1">{Math.round(st.age_seconds)}s</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </ChartShell>

      {/* Run history. */}
      <ChartShell
        title="Run history"
        sub="Every dashboard terminal launch (metadata only - project roots and correlation tokens are stored hashed, never in the clear). Correlated session appears once the launch produces one."
      >
        <div className="max-h-[320px] overflow-auto p-1 text-[11px]">
          {(runs.data?.runs.length ?? 0) === 0 ? (
            <div className="text-fg-3">No terminal runs yet.</div>
          ) : (
            <table className="w-full text-left font-mono">
              <thead className="text-fg-3">
                <tr>
                  <th className="py-1">launched</th>
                  <th className="py-1">tool</th>
                  <th className="py-1">kind</th>
                  <th className="py-1">state</th>
                  <th className="py-1">session</th>
                  <th className="py-1">cmds</th>
                </tr>
              </thead>
              <tbody className="text-fg-2">
                {runs.data?.runs.map((r) => (
                  <tr key={r.run_id} className="border-t border-line-1">
                    <td className="py-1 pr-2">{fmtClock(r.launched_at)}</td>
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
                        <span title={`${r.best_session_id} · confidence ${(r.best_confidence ?? 0).toFixed(2)}`}>
                          {fmtShortId(r.best_session_id, 10)}
                        </span>
                      ) : (
                        <span className="text-fg-3">-</span>
                      )}
                    </td>
                    <td className="py-1">{r.command_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </ChartShell>
        </>
      )}
    </div>
  );
}

type TerminalSandboxConfig = {
  enabled: boolean;
  backend: string;
  home_mode: "tmpfs" | "readonly";
  default_on: boolean;
  allow_remote_clone: boolean;
  remote_allowed_hosts: string[];
  allow_worktree_source: boolean;
  workspaces_dir: string;
  workspace_retention_days: number;
  mask_paths: string[];
  extra_ro_binds: string[];
  extra_rw_binds: string[];
  prep_timeout_seconds: number;
};

type TerminalSandboxConfigResponse = {
  confirm_token: ConfirmToken;
  config_writable: boolean;
  restart_required_on_save: boolean;
  sandbox: TerminalSandboxConfig;
};

type ConfirmToken = string;

function splitConfigList(value: string): string[] {
  // Preserve a trailing empty row while the operator types; the server trims
  // and de-duplicates on save. Filtering here would eat each newly-entered
  // newline and make multi-line editing impossible in a controlled textarea.
  return value.replace(/\r/g, "").split("\n");
}

// SandboxSettingsCard is the missing dashboard editor for the complete
// [terminal.sandbox] block. The live probe is intentionally shown alongside
// the saved config: a save binds only after restart, so the UI never implies
// that a newly-enabled sandbox is already protecting launches.
function SandboxSettingsCard() {
  const settings = useApi<TerminalSandboxConfigResponse>(
    "/api/terminal/sandbox/config",
  );
  const probe = useApi<SandboxAvailability>("/api/terminal/sandbox");
  const [draft, setDraft] = useState<TerminalSandboxConfig | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (settings.data?.sandbox) setDraft(settings.data.sandbox);
  }, [settings.data]);

  function update<K extends keyof TerminalSandboxConfig>(
    key: K,
    value: TerminalSandboxConfig[K],
  ) {
    setSaved(false);
    setDraft((cur) => (cur ? { ...cur, [key]: value } : cur));
  }

  async function saveSandbox() {
    if (!draft || !settings.data?.confirm_token) {
      setErr("Sandbox settings are not ready - reload the page.");
      return;
    }
    if (
      (draft.allow_remote_clone || draft.extra_rw_binds.some((p) => p.trim() !== "")) &&
      !window.confirm(
        "This sandbox configuration expands authority: remote clone lets the daemon make a network git request with your ambient credentials, and read-write binds expose host paths inside the sandbox. Save these settings?",
      )
    ) {
      return;
    }
    setBusy(true);
    setErr(null);
    setSaved(false);
    try {
      const res = await fetchJSON<{ restart_required: boolean }>(
        "/api/terminal/sandbox/config",
        undefined,
        {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
            "X-Observer-Confirm": settings.data.confirm_token,
          },
          body: JSON.stringify(draft),
        },
      );
      if (res.restart_required) markRestartPending("terminal-sandbox");
      setSaved(true);
      settings.reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const writable = !!settings.data?.config_writable;
  const live = probe.data;

  return (
    <ChartShell
      title="Sandbox isolation"
      sub="Run supported agents inside bubblewrap with an isolated home and an explicit workspace. Saved settings bind on the next daemon restart."
      right={
        <Pill variant={live?.available ? "success" : "neutral"}>
          {live?.available ? "available now" : "not active"}
        </Pill>
      }
    >
      <div className="space-y-4 p-1 text-[12px]">
        {!writable && settings.data && (
          <div className="rounded-2 border border-line-2 bg-bg-2 px-3 py-2 text-fg-3">
            This dashboard has no writable config path. Edit{" "}
            <code className="text-fg-2">[terminal.sandbox]</code> in config.toml instead.
          </div>
        )}

        <div
          className={`rounded-2 border px-3 py-2 ${
            live?.available
              ? "border-ok/40 bg-ok/10 text-ok"
              : "border-line-2 bg-bg-2 text-fg-3"
          }`}
        >
          <span className="font-medium">Running daemon: </span>
          {live?.available
            ? `${live.backend ?? "bwrap"} ${live.backend_version ?? ""} available; home is ${live.home_mode ?? "isolated"}.`
            : live?.reason ?? "Sandbox probe has not returned yet."}
          {draft?.enabled && !live?.available && (
            <span className="ml-1 text-warn">
              If you just enabled it, restart the daemon before relying on the boundary.
            </span>
          )}
        </div>

        {!draft ? (
          <div className="text-fg-3">Loading sandbox configuration…</div>
        ) : (
          <>
            <div className="grid gap-3 md:grid-cols-2">
              <label className="flex items-start gap-2 rounded-2 border border-line-2 bg-bg-1 p-3">
                <input
                  type="checkbox"
                  className="mt-0.5"
                  checked={draft.enabled}
                  disabled={!writable}
                  onChange={(e) => update("enabled", e.target.checked)}
                />
                <span>
                  <span className="font-medium text-fg-1">Enable sandbox support</span>
                  <span className="block text-[11px] text-fg-3">
                    Master switch. Supported launches may use the boundary after restart.
                  </span>
                </span>
              </label>
              <label className="flex items-start gap-2 rounded-2 border border-line-2 bg-bg-1 p-3">
                <input
                  type="checkbox"
                  className="mt-0.5"
                  checked={draft.default_on}
                  disabled={!writable}
                  onChange={(e) => update("default_on", e.target.checked)}
                />
                <span>
                  <span className="font-medium text-fg-1">Default sandbox on</span>
                  <span className="block text-[11px] text-fg-3">
                    Pre-check “Run in sandbox” for each new-terminal launch; it remains overridable.
                  </span>
                </span>
              </label>
            </div>

            <div className="grid gap-3 md:grid-cols-2">
              <label className="space-y-1">
                <span className="font-medium text-fg-1">Home isolation</span>
                <select
                  value={draft.home_mode}
                  disabled={!writable}
                  onChange={(e) => update("home_mode", e.target.value as "tmpfs" | "readonly")}
                  className="w-full rounded-2 border border-line-2 bg-bg-1 px-2 py-1 text-fg-1 disabled:opacity-50"
                >
                  <option value="tmpfs">tmpfs - hide the real home (recommended)</option>
                  <option value="readonly">readonly - expose the real home read-only</option>
                </select>
              </label>
              <label className="space-y-1">
                <span className="font-medium text-fg-1">Backend</span>
                <input
                  value={draft.backend}
                  readOnly
                  className="w-full rounded-2 border border-line-2 bg-bg-2 px-2 py-1 font-mono text-fg-3"
                />
                <span className="block text-[11px] text-fg-3">bwrap is the only v1 backend.</span>
              </label>
            </div>

            <div className="grid gap-3 md:grid-cols-2">
              <label className="flex items-start gap-2 rounded-2 border border-warn/30 bg-warn/5 p-3">
                <input
                  type="checkbox"
                  className="mt-0.5"
                  checked={draft.allow_remote_clone}
                  disabled={!writable}
                  onChange={(e) => update("allow_remote_clone", e.target.checked)}
                />
                <span>
                  <span className="font-medium text-fg-1">Allow remote clone</span>
                  <span className="block text-[11px] text-fg-3">
                    The daemon may run git clone over the network with your ambient credentials.
                  </span>
                </span>
              </label>
              <label className="flex items-start gap-2 rounded-2 border border-warn/30 bg-warn/5 p-3">
                <input
                  type="checkbox"
                  className="mt-0.5"
                  checked={draft.allow_worktree_source}
                  disabled={!writable}
                  onChange={(e) => update("allow_worktree_source", e.target.checked)}
                />
                <span>
                  <span className="font-medium text-fg-1">Allow git worktree source</span>
                  <span className="block text-[11px] text-fg-3">
                    Requires the main repo&apos;s .git directory read-write inside the boundary.
                  </span>
                </span>
              </label>
            </div>

            <SandboxListField
              label="Remote allowed hosts"
              hint="One hostname per line. Empty means any host once remote clone is enabled."
              value={draft.remote_allowed_hosts}
              disabled={!writable}
              onChange={(v) => update("remote_allowed_hosts", v)}
            />

            <details className="rounded-2 border border-line-2 bg-bg-1 p-3">
              <summary className="cursor-pointer font-medium text-fg-1">
                Workspace lifecycle and advanced binds
              </summary>
              <div className="mt-3 space-y-3">
                <label className="block space-y-1">
                  <span className="font-medium text-fg-2">Workspaces directory</span>
                  <input
                    value={draft.workspaces_dir}
                    disabled={!writable}
                    placeholder="default: &lt;observer dir&gt;/workspaces"
                    onChange={(e) => update("workspaces_dir", e.target.value)}
                    className="w-full rounded-2 border border-line-2 bg-bg-0 px-2 py-1 font-mono text-[11px] text-fg-1 disabled:opacity-50"
                  />
                  <span className="block text-[11px] text-fg-3">Must be an absolute path when set.</span>
                </label>
                <div className="grid gap-3 sm:grid-cols-2">
                  <label className="space-y-1">
                    <span className="font-medium text-fg-2">Retention days</span>
                    <input
                      type="number"
                      min={0}
                      step={1}
                      value={draft.workspace_retention_days}
                      disabled={!writable}
                      onChange={(e) => update("workspace_retention_days", Number(e.target.value))}
                      className="w-full rounded-2 border border-line-2 bg-bg-0 px-2 py-1 text-fg-1 disabled:opacity-50"
                    />
                    <span className="block text-[11px] text-fg-3">0 keeps prepared workspaces forever.</span>
                  </label>
                  <label className="space-y-1">
                    <span className="font-medium text-fg-2">Preparation timeout (seconds)</span>
                    <input
                      type="number"
                      min={0}
                      step={1}
                      value={draft.prep_timeout_seconds}
                      disabled={!writable}
                      onChange={(e) => update("prep_timeout_seconds", Number(e.target.value))}
                      className="w-full rounded-2 border border-line-2 bg-bg-0 px-2 py-1 text-fg-1 disabled:opacity-50"
                    />
                  </label>
                </div>
                <SandboxListField
                  label="Mask paths"
                  hint="Absolute host paths to hide with tmpfs, one per line."
                  value={draft.mask_paths}
                  disabled={!writable}
                  onChange={(v) => update("mask_paths", v)}
                />
                <SandboxListField
                  label="Extra read-only binds"
                  hint="Absolute paths exposed read-only inside the sandbox."
                  value={draft.extra_ro_binds}
                  disabled={!writable}
                  onChange={(v) => update("extra_ro_binds", v)}
                />
                <SandboxListField
                  label="Extra read-write binds"
                  hint="Authority-expanding: these host paths become writable inside the sandbox."
                  value={draft.extra_rw_binds}
                  disabled={!writable}
                  warn
                  onChange={(v) => update("extra_rw_binds", v)}
                />
              </div>
            </details>

            {err && (
              <div className="rounded-2 border border-danger/40 bg-danger/10 px-3 py-2 text-danger">
                {err}
              </div>
            )}
            <div className="flex flex-wrap items-center gap-3 pt-1">
              <button
                type="button"
                disabled={busy || !writable}
                onClick={saveSandbox}
                className="rounded-2 border border-accent/50 bg-accent/15 px-3 py-1 text-accent hover:bg-accent/25 disabled:opacity-50"
              >
                {busy ? "saving…" : "Save sandbox configuration"}
              </button>
              {saved && <span className="text-[11px] text-ok">Saved.</span>}
              <span className="text-[11px] text-fg-3">
                Restart required; active terminals are not retroactively sandboxed.
              </span>
            </div>
          </>
        )}
      </div>
    </ChartShell>
  );
}

function SandboxListField({
  label,
  hint,
  value,
  disabled,
  warn = false,
  onChange,
}: {
  label: string;
  hint: string;
  value: string[];
  disabled: boolean;
  warn?: boolean;
  onChange: (value: string[]) => void;
}) {
  return (
    <label className="block space-y-1">
      <span className={`font-medium ${warn ? "text-warn" : "text-fg-2"}`}>{label}</span>
      <textarea
        rows={Math.max(2, Math.min(5, value.length + 1))}
        value={value.join("\n")}
        disabled={disabled}
        onChange={(e) => onChange(splitConfigList(e.target.value))}
        className="w-full rounded-2 border border-line-2 bg-bg-0 px-2 py-1 font-mono text-[11px] text-fg-1 disabled:opacity-50"
      />
      <span className="block text-[11px] text-fg-3">{hint}</span>
    </label>
  );
}
