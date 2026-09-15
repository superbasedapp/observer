import { useEffect, useState } from "react";
import { NavLink } from "react-router-dom";
import clsx from "clsx";
import { NAV_GROUPS, type NavIcon } from "@/lib/nav";
import { useApi } from "@/lib/useApi";
import { filterNavGroups, useGovernance } from "@/lib/governance";
import { fmtBytes, fmtCompact } from "@/lib/format";
import {
  BarChartIcon,
  BoltIcon,
  CoinsIcon,
  CompassIcon,
  DatabaseIcon,
  DollarIcon,
  DropletIcon,
  EyeIcon,
  GearIcon,
  LayersIcon,
  LightningIcon,
  ListIcon,
  PercentIcon,
  SearchIcon,
  ShieldIcon,
  SparklesIcon,
  WrenchIcon,
} from "@/components/icons";
import { Tooltip } from "@/components/primitives";
import type { StatusSnapshot, SetupClaude, WatcherHealth } from "@/lib/types";

function NavIconSvg({ icon }: { icon: NavIcon }) {
  switch (icon) {
    case "overview":
      return <EyeIcon size={13} />;
    case "live":
      return <BoltIcon size={13} />;
    case "search":
      return <SearchIcon size={13} />;
    case "sessions":
      return <ListIcon size={13} />;
    case "actions":
      return <LightningIcon size={13} />;
    case "security":
      return <ShieldIcon size={13} />;
    case "egress":
      return <CompassIcon size={13} />;
    case "policies":
      return <LayersIcon size={13} />;
    case "cost":
      return <DollarIcon size={13} />;
    case "analysis":
      return <BarChartIcon size={13} />;
    case "tools":
      return <WrenchIcon size={13} />;
    case "compression":
      return <DropletIcon size={13} />;
    case "cache":
      return <DatabaseIcon size={13} />;
    case "suggestions":
      return <CoinsIcon size={13} />;
    case "benchmarks":
      return <PercentIcon size={13} />;
    case "discovery":
      return <SearchIcon size={13} />;
    case "patterns":
      return <SparklesIcon size={13} />;
    case "privacy":
      return <ShieldIcon size={13} />;
    case "remote":
      return <CompassIcon size={13} />;
    case "settings":
      return <GearIcon size={13} />;
  }
}

export function Sidebar({
  open = false,
  onClose,
}: {
  // open/onClose drive the mobile (< lg) overlay drawer. On desktop the
  // sidebar is a static sibling and these are inert.
  open?: boolean;
  onClose?: () => void;
} = {}) {
  // Live-capture refresh: 5s on the status snapshot, so the sidebar's nav
  // counts follow fresh activity within seconds. Note the 5s is the POLL
  // cadence, not the freshness guarantee — the daemon memoizes /api/status
  // for ~15s because it is an unfiltered scan of every table, so on a large
  // database a count can lag reality by up to ~20s. Fine for badges; do not
  // build anything that needs to-the-second accuracy on these numbers.
  const status = useApi<StatusSnapshot>("/api/status", undefined, [], { refreshMs: 5000 });
  const setupClaude = useApi<SetupClaude>("/api/setup/claude");
  // Watcher health (P1.7): behind/orphan/misroute counts only — a
  // slow 60s cadence is plenty for a lag signal.
  const watcherHealth = useApi<WatcherHealth>("/api/health/watcher", undefined, [], {
    refreshMs: 60000,
  });
  // Governed nodes (enrolled + granted dashboard.visibility authority)
  // may have nav sections hidden by their organization — a no-op on
  // an ordinary solo node (gov.data is {active: false, ...} or null
  // while loading, both of which filterNavGroups passes through
  // unchanged).
  const gov = useGovernance();
  const navGroups = filterNavGroups(NAV_GROUPS, gov.data);
  const counts = navCounts(status.data);
  // Desktop (lg+) icon-only rail collapse. The pref is persisted in
  // localStorage ("1"/"0", ProcessesSection pattern) and only bites at
  // lg+ — the mobile drawer keeps full width + labels regardless (the
  // collapsed classes are all `lg:` variants). The unused
  // --sidebar-w-collapsed token (tokens.css) is wired here at last.
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    try {
      return localStorage.getItem("sb_nav_collapsed") === "1";
    } catch {
      return false;
    }
  });
  function toggleCollapsed() {
    setCollapsed((v) => {
      const next = !v;
      try {
        localStorage.setItem("sb_nav_collapsed", next ? "1" : "0");
      } catch {
        /* ignore — persistence is best-effort */
      }
      return next;
    });
  }
  // Footer "refreshed Xs ago" — recomputes every second so the clock
  // walks even between /api/status fetches.
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const id = window.setInterval(() => setTick((t) => t + 1), 5000);
    return () => window.clearInterval(id);
  }, []);
  void tick;
  return (
    <>
      {/* Backdrop — only on mobile while the drawer is open. Tapping it
          closes the drawer. Hidden entirely at lg+ (static sidebar). */}
      {open && (
        <div
          className="fixed inset-0 z-30 bg-black/50 lg:hidden"
          aria-hidden
          onClick={onClose}
        />
      )}
      <aside
        className={clsx(
          "flex w-[var(--sidebar-w)] shrink-0 flex-col border-r border-line-1 bg-bg-1",
          // Mobile: fixed overlay drawer that slides in from the left.
          // Desktop (lg+): a normal static flex sibling, always visible.
          // Width AND transform animate so the desktop collapse and the
          // mobile slide both tween smoothly.
          "fixed inset-y-0 left-0 z-40 transition-[transform,width] duration-200 ease-out lg:static lg:z-auto lg:translate-x-0",
          open ? "translate-x-0" : "-translate-x-full",
          // Collapse is desktop-only: shrink to the icon rail at lg+ while
          // the mobile drawer keeps the full 220px.
          collapsed && "lg:w-[var(--sidebar-w-collapsed)]",
        )}
      >
        <Brand onClose={onClose} collapsed={collapsed} />
        <nav className="flex-1 overflow-y-auto px-3 py-4">
          {navGroups.map((g) => (
            <div key={g.id} className="mb-5">
              <div
                className={clsx(
                  "mb-2 px-2 text-[10px] font-semibold uppercase tracking-[0.08em] text-fg-3",
                  // Group labels are noise on the icon rail — hide at lg+
                  // when collapsed; the mobile drawer still shows them.
                  collapsed && "lg:hidden",
                )}
              >
                {g.label}
              </div>
              {g.items.map((it) => (
                // Collapsed-rail affordance: a themed tooltip (side="right"
                // reads naturally on a left rail) shows the label only when
                // the rail is collapsed; the expanded rail stays tooltip-free
                // (content={null} makes Tooltip a no-op passthrough).
                <Tooltip
                  key={it.id}
                  content={collapsed ? it.label : null}
                  side="right"
                >
                  <NavLink
                    to={it.path}
                    end={it.path === "/"}
                    onClick={onClose}
                    data-tour={`nav-${it.id}`}
                    className={({ isActive }) =>
                      clsx(
                        "flex items-center gap-2 rounded-2 px-2 py-1.5 text-[12.5px] transition-colors",
                        collapsed && "lg:justify-center",
                        isActive
                          ? "bg-bg-3 text-fg-0"
                          : "text-fg-2 hover:bg-bg-2 hover:text-fg-1",
                      )
                    }
                  >
                    <span className="shrink-0 text-fg-3">
                      <NavIconSvg icon={it.icon} />
                    </span>
                    <span
                      className={clsx("flex-1 truncate", collapsed && "lg:hidden")}
                    >
                      {it.label}
                    </span>
                    {counts[it.id] != null && (
                      <span
                        className={clsx(
                          "shrink-0 font-mono text-[10px] tabular-nums text-fg-4",
                          collapsed && "lg:hidden",
                        )}
                      >
                        {fmtCompact(counts[it.id] as number)}
                      </span>
                    )}
                  </NavLink>
                </Tooltip>
              ))}
            </div>
          ))}
        </nav>
        {/* Desktop-only collapse toggle — always reachable (visible in
            both expanded and collapsed states). Centered on the rail
            when collapsed; labeled when expanded. */}
        <Tooltip
          content={collapsed ? "Expand navigation" : "Collapse navigation"}
          side="right"
        >
          <button
            type="button"
            onClick={toggleCollapsed}
            aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
            className={clsx(
              "hidden items-center gap-2 border-t border-line-1 px-3 py-2 text-[11px] text-fg-3 transition-colors hover:bg-bg-2 hover:text-fg-1 lg:flex",
              collapsed && "lg:justify-center",
            )}
          >
            <span className="grid h-6 w-6 shrink-0 place-items-center">
              <ChevronCollapseIcon collapsed={collapsed} />
            </span>
            {!collapsed && <span>Collapse</span>}
          </button>
        </Tooltip>
        {/* Governed-node notice — persistent, never a silent absence.
            Only renders when this machine is actually governed AND
            pages were actually hidden, so it never appears on a solo
            node. Hidden at lg+ when collapsed for the same overflow
            reason as Foot below. */}
        {gov.data?.active && gov.data.hidden_sections.length > 0 && (
          <NavLink
            to="/settings"
            onClick={onClose}
            className={clsx(
              "block border-t border-line-1 px-4 py-2 text-[10.5px] text-fg-3 hover:bg-bg-2 hover:text-fg-1",
              collapsed && "lg:hidden",
            )}
          >
            Some pages are hidden by your organization
          </NavLink>
        )}
        {/* Footer detail overflows the 56px rail — hide it at lg+ when
            collapsed. The mobile drawer (always full width) keeps it. */}
        <div className={clsx(collapsed && "lg:hidden")}>
          <Foot
            setup={setupClaude.data}
            status={status.data}
            watcher={watcherHealth.data}
          />
        </div>
      </aside>
    </>
  );
}

// ChevronCollapseIcon — points left (« collapse) when expanded, right
// (» expand) when collapsed, mirroring the rail's motion direction.
function ChevronCollapseIcon({ collapsed }: { collapsed: boolean }) {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 16 16"
      fill="none"
      aria-hidden
      style={{ transform: collapsed ? "rotate(180deg)" : undefined }}
    >
      <path
        d="M10 3.5 5.5 8 10 12.5"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function Brand({
  onClose,
  collapsed = false,
}: {
  onClose?: () => void;
  collapsed?: boolean;
}) {
  return (
    <div
      className={clsx(
        "flex h-[var(--header-h)] items-center gap-2 border-b border-line-1 px-4",
        // Center the logo on the icon rail (lg+ collapsed); the mobile
        // drawer keeps the full brand row.
        collapsed && "lg:justify-center lg:gap-0 lg:px-2",
      )}
    >
      {/* The ▞ superbased wordmark, matching the marketing site's .sb-brand
          exactly: the U+259E glyph (QUADRANT UPPER RIGHT AND LOWER LEFT) tinted
          Blueprint blue, then lowercase "superbased" in the mono face. This is
          the standalone glyph mark - NOT a badge box, NOT title case. */}
      <span
        aria-hidden
        className="shrink-0 font-mono text-[21px] font-semibold leading-none"
        style={{ color: "#2647E8" }}
      >
        {"▞"}
      </span>
      <div
        className={clsx(
          "flex flex-col leading-tight",
          collapsed && "lg:hidden",
        )}
      >
        <b className="font-mono text-[15px] font-medium tracking-tight text-fg-0">
          superbased
        </b>
      </div>
      {/* Close button — mobile drawer only. */}
      <button
        type="button"
        onClick={onClose}
        aria-label="Close navigation"
        className="ml-auto grid h-7 w-7 place-items-center rounded-2 border border-line-2 bg-bg-2 text-fg-3 hover:bg-bg-3 hover:text-fg-0 lg:hidden"
      >
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden>
          <path
            d="M4 4l8 8M12 4l-8 8"
            stroke="currentColor"
            strokeWidth="1.5"
            strokeLinecap="round"
          />
        </svg>
      </button>
    </div>
  );
}

// navCounts maps each NavItem.id to a compact stat for the right
// gutter. Every data page carries a badge; only Overview (the home)
// and the Configure group (Privacy / Settings — no event streams)
// stay deliberately un-badged. The newer fields (live_sessions /
// guard_events / router_decisions) are optional in the type because
// an older daemon may serve a /api/status without them — `?? null`
// keeps those badges hidden instead of rendering a bogus 0.
function navCounts(s?: StatusSnapshot | null): Record<string, number | null> {
  if (!s) return {};
  const c = s.counts;
  return {
    live: c.live_sessions ?? null,
    sessions: c.sessions,
    actions: c.actions,
    security: c.guard_events ?? null,
    // The search corpus IS the FTS5 excerpt index — same substrate the
    // Compression badge counts, surfaced here as "how much is searchable".
    search: c.action_excerpts,
    cost: c.api_turns,
    analysis: c.token_usage,
    tools: distinctTools(s),
    compression: c.action_excerpts,
    cache: c.cache_events,
    suggestions: c.suggestions,
    routing: c.router_decisions ?? null,
    discovery: c.file_state,
    patterns: c.projects,
    // settings and overview stay un-badged
  };
}

function distinctTools(s: StatusSnapshot): number {
  return s.per_tool_last_seen?.length ?? 0;
}

function Foot({
  setup,
  status,
  watcher,
}: {
  setup: SetupClaude | null;
  status: StatusSnapshot | null;
  watcher: WatcherHealth | null;
}) {
  const proxyOn =
    setup != null &&
    (setup.status === "oauth_ready" || setup.status === "api_key_ready");
  // Watcher-lag signal (P1.7): transcripts the watcher is behind on
  // risk dropped capture; misroute/orphan cursors mean rows silently
  // not landing. Surface a warn line the moment either is non-zero.
  //
  // Both counts arrive already filtered by cursor semantics: rows
  // whose saved cursor is a SQLite watermark, whose store is
  // encrypted, or which never emit actions by design are excluded
  // server-side (they're still listed in `files` with a cursor_kind +
  // excluded_reason). Without that filter these numbers were
  // dominated by files the recovery flow can never close, so the warn
  // line could never go away — see help "glossary.watcher_lag".
  const lagging = (watcher?.behind_count ?? 0) > 0;
  const misrouted = (watcher?.suspected_misrouted_count ?? 0) > 0;
  return (
    <div className="border-t border-line-1 px-4 py-3 text-[11px] text-fg-3">
      <div className="mb-0.5 flex items-center gap-1.5 text-fg-2">
        <span
          className={clsx(
            "relative h-1.5 w-1.5 rounded-full",
            proxyOn ? "bg-success" : "bg-warn",
          )}
        >
          {proxyOn && (
            <span className="absolute inset-0 -m-0.5 animate-ping rounded-full bg-success/40" />
          )}
        </span>
        watcher {proxyOn ? "active" : "-"}
        {setup?.proxy_port ? (
          <>
            {" · "}
            <span className="font-mono text-fg-3">
              proxy {setup.proxy_port}
            </span>
          </>
        ) : null}
      </div>
      {(lagging || misrouted) && (
        <Tooltip
          maxWidth={320}
          content={
            (lagging
              ? `Watcher is behind on ${watcher!.behind_count} append-only transcript(s) (${fmtBytes(watcher!.behind_total_bytes)} unread) - recent activity may not be captured yet. A rescan (Settings → Backfill) catches up if it persists. `
              : "") +
            (misrouted
              ? `${watcher!.suspected_misrouted_count} transcript(s) look misrouted (cursor at EOF, zero rows emitted). `
              : "") +
            "Files whose cursor is a SQLite watermark, whose store is encrypted, or that only ever carry tokens are excluded from both counts - that comparison can't close, so counting it would pin this warning on forever."
          }
        >
          {/* tabIndex={0} makes the warning keyboard-focusable so the Tooltip
              (which opens on focus) is reachable without a pointer. */}
          <div tabIndex={0} className="mb-0.5 flex items-center gap-1.5 text-[10px] text-warn">
            <span className="h-1.5 w-1.5 rounded-full bg-warn" />
            {lagging && <>behind {watcher!.behind_count} file{watcher!.behind_count === 1 ? "" : "s"}</>}
            {lagging && misrouted && " · "}
            {misrouted && <>{watcher!.suspected_misrouted_count} misrouted</>}
          </div>
        </Tooltip>
      )}
      {status && (
        <div className="font-mono text-[10px] text-fg-4">
          schema v{status.schema_version}
          {status.db_size_bytes != null && (
            <> · {fmtBytes(status.db_size_bytes)}</>
          )}
          {status.uptime_seconds != null && status.uptime_seconds > 0 && (
            <> · up {fmtUptime(status.uptime_seconds)}</>
          )}
        </div>
      )}
      {status?.last_action_at && (
        <div className="font-mono text-[10px] text-fg-4">
          last activity {fmtRelative(status.last_action_at)} ago
        </div>
      )}
    </div>
  );
}

function fmtUptime(sec: number): string {
  if (sec < 3600) return `${Math.max(1, Math.floor(sec / 60))}m`;
  const hr = Math.floor(sec / 3600);
  if (hr < 48) return `${hr}h`;
  return `${Math.floor(hr / 24)}d`;
}

function fmtRelative(iso: string): string {
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return "-";
  const sec = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (sec < 60) return `${sec}s`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h`;
  return `${Math.floor(hr / 24)}d`;
}
