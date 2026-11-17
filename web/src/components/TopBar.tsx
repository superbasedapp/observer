import { useEffect, useState } from "react";
import { Link as RouterLink, useLocation } from "react-router-dom";
import clsx from "clsx";
import {
  ArrowUp,
  CircleHelp,
  Download,
  ExternalLink,
  Menu,
  RefreshCw,
  UserRound,
} from "lucide-react";
import { NAV_GROUPS } from "@/lib/nav";
import { exportTargetFor } from "@/lib/exportTarget";
import { exportJSONText } from "@/lib/costExport";
import { useFilters, windowParams } from "@/lib/filters";
import { nodeTabCrumb } from "@/lib/pageTabRoutes";
import { useApi, useApiActivity } from "@/lib/useApi";
import { fmtDuration } from "@/lib/format";
import { useTheme } from "@/lib/theme";
import { ThemeToggle as SharedThemeToggle } from "@shared/primitives/ThemeToggle";
import type { EnrolmentStatus, SetupClaude, StatusSnapshot } from "@/lib/types";
import { isUpdateAvailable, useUpdateCheck } from "@/lib/version";
import { npmUpdateCommand } from "@/lib/npmCommand";
import { useHostOS } from "@/lib/keyPlatform";
import { Icon, LiveDot, Tooltip } from "@/components/primitives";
import { DensityToggle } from "@shared/primitives/DensityToggle";
import { PageLinkTools } from "@shared/primitives";
import { DENSITY_STORAGE_KEY } from "@shared/lib/density";
import { useDensity } from "@shared/lib/useDensity";
import {
  ACTIVITY_DOT,
  CAPTURE_DOT,
  CLOUD_SIGN_IN_DOT,
  liveDotProps,
  withDotClass,
} from "@/lib/liveSignals";
import { topBarAccountView } from "@/lib/getStarted";
import { useAccount, useConnectFlow } from "@/lib/useConnectFlow";
import { capturePillView, type CapturePillState } from "@/lib/capturePill";
import { InstanceSwitcher } from "@/components/InstanceSwitcher";
import { RemoteMachineChip } from "@/components/RemoteMachineChip";
import { NotificationBell } from "@/components/NotificationBell";
import { avatarInitials, identityLabel, type MeMachine } from "@/lib/you";
import { PhoneTerminalButton } from "@/components/LaunchDock";

// `dashboard-refresh` is a window-level CustomEvent that useApi
// listens for to re-fire its fetch. TopBar's Refresh button is the
// only emitter for now; later we may add a per-window-blur retry.
export const REFRESH_EVENT = "dashboard-refresh";


export function TopBar({
  onHelp,
  onMenu,
}: {
  onHelp?: () => void;
  // onMenu opens the mobile nav drawer (< lg). Renders a hamburger.
  onMenu?: () => void;
}) {
  const { pathname, search } = useLocation();
  // The open page tab is the breadcrumb's last segment (lib/pageTabRoutes.ts,
  // the table the command palette reads too); a default tab adds nothing.
  const tabLabel = nodeTabCrumb(pathname, search);
  const group = NAV_GROUPS.find((g) =>
    g.items.some((i) => i.path === pathname),
  );
  const item = group?.items.find((i) => i.path === pathname);
  // Live-capture refresh: 5s on the lightweight status surface so the
  // header's "last seen" and counters stay current. Setup config is
  // static; no refresh.
  // The header reads two fields; select them so a poll that only moves the
  // per-request fields (uptime) does not re-render the header.
  const status = useApi<StatusSnapshot, TopBarStatus>("/api/status", undefined, [], {
    refreshMs: 5000,
    select: selectTopBarStatus,
  });
  const setup = useApi<SetupClaude>("/api/setup/claude");
  const lastSeen = status.data?.last_action_at;

  function refresh() {
    window.dispatchEvent(new CustomEvent(REFRESH_EVENT));
  }

  // Export downloads the page's own data with the filters the page shows
  // (lib/exportTarget.ts, one table); a page with nothing to export says so
  // instead of downloading the status snapshot.
  const { win, customRange, tool, project, model } = useFilters();
  const exportTarget = exportTargetFor(pathname, search, {
    window: windowParams(win, customRange),
    tool,
    project,
    model,
  });
  const exportNone = "none" in exportTarget ? exportTarget.none : null;
  const [exportError, setExportError] = useState<string | null>(null);
  useEffect(() => setExportError(null), [pathname, search]);

  async function exportCurrent() {
    if ("none" in exportTarget) return;
    setExportError(null);
    try {
      const res = await fetch(exportTarget.url);
      if (!res.ok) {
        // A refused read (a hidden page, a local-only route on a remote
        // view) is reported, never downloaded as if it were the data.
        setExportError(`Export failed (HTTP ${res.status})`);
        return;
      }
      // The download follows the developer cost display (T-204): in the
      // token-usage view its dollar fields are left out (lib/costExport).
      const blob = new Blob([exportJSONText(await res.text())], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${item?.id ?? "data"}-${new Date()
        .toISOString()
        .slice(0, 10)}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      setExportError(e instanceof Error ? `Export failed: ${e.message}` : "Export failed");
    }
  }

  return (
    <header className="flex h-[var(--header-h)] items-center justify-between gap-3 border-b border-line-1 bg-bg-1 px-3 sm:px-5">
      {/* The breadcrumb side takes the room that is left and truncates
          first; the status side never wraps or shrinks (demo bug #10: at
          1,600 px the chips wrapped onto two lines - "last / activity",
          "Enrolled in / localhost:8443" - while the breadcrumb was cut to
          "Securi... / Prompt gu..."). */}
      <div className="flex min-w-0 flex-1 items-center gap-2 text-[12px] text-fg-3">
        {onMenu && (
          <button
            type="button"
            onClick={onMenu}
            aria-label="Open navigation"
            className="grid h-7 w-7 shrink-0 place-items-center rounded-2 border border-line-2 bg-bg-2 text-fg-2 hover:bg-bg-3 hover:text-fg-0 lg:hidden"
          >
            <Icon icon={Menu} size={15} />
          </button>
        )}
        {group && (
          <div className="flex min-w-0 items-center gap-2">
            <span className="hidden sm:inline">{group.label}</span>
            <span className="hidden sm:inline">/</span>
            {tabLabel ? (
              <>
                <RouterLink to={pathname} className="truncate hover:text-fg-1">
                  {item?.label ?? "-"}
                </RouterLink>
                <span>/</span>
                <b className="truncate text-fg-1">{tabLabel}</b>
              </>
            ) : (
              <b className="truncate text-fg-1">{item?.label ?? "-"}</b>
            )}
          </div>
        )}
        <RemoteMachineChip />
      </div>
      <div className="flex shrink-0 items-center gap-2 whitespace-nowrap text-[11px] text-fg-3">
        {/* Secondary status + Export — hidden on phones (< md) to keep
            the header uncluttered; the drawer + Refresh stay reachable.
            Between md and xl the column is too narrow for every chip (at
            1,024 px they ran about 100 px past the edge and gave the page a
            horizontal scrollbar, 2026-11-06), so the lowest-value ones
            (last activity, the cloud chip, density, the link tools) wait
            for xl. */}
        <div className="hidden items-center gap-2 md:flex">
          <span className="hidden xl:inline-flex">
            <LastActivity iso={lastSeen} />
          </span>
          <UpdateAvailablePill current={status.data?.version} />
          <CaptureStatePill setup={setup.data} />
          {/* Instance switcher — renders nothing unless the operator has
              configured [[terminal.ssh.profiles]], so a solo install's header
              is unchanged. */}
          <InstanceSwitcher />
          <div className="mx-1 h-4 w-px bg-line-2" />
          {exportError && (
            <span role="status" className="text-[11px] text-danger">
              {exportError}
            </span>
          )}
          <Tooltip content={exportNone ?? "Export the current page's data as JSON, with the filters in view"}>
            <button
              type="button"
              onClick={exportCurrent}
              aria-disabled={exportNone != null}
              aria-label={exportNone ? `Export: ${exportNone}` : "Export the current page's data as JSON"}
              className={clsx(
                "flex h-7 items-center gap-1.5 rounded-2 border border-line-2 bg-bg-2 px-2.5 text-[11px]",
                exportNone ? "cursor-not-allowed text-fg-4" : "text-fg-2 hover:bg-bg-3 hover:text-fg-0",
              )}
            >
              <Icon icon={Download} size="xs" />
              Export
            </button>
          </Tooltip>
        </div>
        {/* The account control (Getting started v2): Sign in, or where this
            machine is connected with Open online, at EVERY width. It
            replaced the widest-only sentence chip, the enrolment chip and
            the cloud sign-in chip. */}
        <AccountControl />
        <Tooltip content="Reload data on every visible card">
          <button
            type="button"
            onClick={refresh}
            className="sb-press flex h-7 items-center gap-1.5 rounded-2 bg-accent px-2.5 text-[11px] font-semibold text-accent-on hover:bg-accent-strong"
          >
            {/* Spins while any foreground request is in flight, so a click
                visibly does something (the refetch itself is silent). */}
            <RefreshGlyph />
            <span className="hidden sm:inline">Refresh</span>
          </button>
        </Tooltip>
        {/* Extra link tools: desktop only (low value on a phone). The
            shared PageLinkTools, the same pair the org top bar carries. */}
        <div className="hidden items-center gap-2 xl:flex">
          <div className="mx-1 h-4 w-px bg-line-2" />
          <PageLinkTools />
        </div>
        {/* The notification bell (D-323): what needs the developer, from
            the daemon's feed. Renders nothing on a remote view. */}
        {/* Below lg the floating terminal dock is hidden (it sat on
            primary actions like Send); its compact top-bar button takes its
            place (T-855). */}
        <span className="inline-flex lg:hidden">
          <PhoneTerminalButton />
        </span>
        <NotificationBell />
        {/* Display preferences are low value on a phone, where the bar
            needs the room for the page title: below sm they live in the
            navigation drawer instead (Sidebar, DisplayControls). */}
        <span className="hidden items-center gap-2 sm:flex">
          <span className="hidden xl:inline-flex">
            <TopBarDensity />
          </span>
          <ThemeToggle dataTour="topbar-theme" />
        </span>
        {onHelp && (
          <span data-tour="topbar-help" className="inline-flex">
            <IconButton
              title={<>Help <kbd>?</kbd></>}
              onClick={onHelp}
            >
              <Icon icon={CircleHelp} size="sm" />
            </IconButton>
          </span>
        )}
        <YouChip />
      </div>
    </header>
  );
}

// Light / Dark / System: the shared ThemeToggle over the shared theme state.
function ThemeToggle({ dataTour }: { dataTour?: string }) {
  const { mode, setMode, modes } = useTheme();
  return <SharedThemeToggle value={mode} onChange={setMode} modes={modes} dataTour={dataTour} />;
}

/** DisplayControls is the density and theme pair for the phone navigation
 *  drawer: below sm the top bar hides them so the page title has room. */
export function DisplayControls() {
  return (
    <span className="flex items-center gap-2">
      <TopBarDensity />
      <ThemeToggle />
    </span>
  );
}

// Comfortable / Compact row density, beside the theme control (both are
// per-browser display preferences). Icons only in the bar; the words stay
// available to screen readers and in the tooltip.
function TopBarDensity() {
  const [density, setDensity] = useDensity(DENSITY_STORAGE_KEY.web);
  return (
    <Tooltip content="Density: Comfortable or Compact">
      <span className="inline-flex">
        <DensityToggle value={density} onChange={setDensity} labels="hidden" />
      </span>
    </Tooltip>
  );
}

type TopBarStatus = { last_action_at?: string; version?: string };

function selectTopBarStatus(s: StatusSnapshot): TopBarStatus {
  return { last_action_at: s.last_action_at, version: s.version };
}

function LastActivity({ iso }: { iso?: string }) {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!iso) return;
    const id = window.setInterval(() => setTick((t) => t + 1), 5000);
    return () => window.clearInterval(id);
  }, [iso]);
  // tick is read to force a re-render every 5s so the relative
  // string updates without re-fetching /api/status.
  void tick;
  if (!iso) return null;
  const ms = Date.now() - new Date(iso).getTime();
  if (!Number.isFinite(ms)) return null;
  const fresh = ms < 60_000;
  return (
    <span className="flex items-center gap-1.5">
      <LiveDot {...withDotClass(liveDotProps(ACTIVITY_DOT, fresh ? "live" : "idle"), "h-1.5 w-1.5 shrink-0")} />
      last activity{" "}
      <span className="text-fg-2">{fmtDuration(ms)} ago</span>
    </span>
  );
}

// UpdateAvailablePill surfaces a subtle "↑ vX.Y.Z available" chip when
// the running daemon (per /api/status's version field) is behind the
// latest @superbased/observer release on npm. Clicking opens the
// GitHub release notes. Renders nothing on dev builds, when the
// version field is empty, when the install is already up-to-date, or
// (as of the zero-network hardening pass) when no one has clicked
// "Check for updates" yet in this tab (or a prior tab within the last
// 6h) — so the header is identical to today's surface on the happy
// path. This component NEVER triggers the npm fetch itself; it only
// reads whatever useUpdateCheck() hydrated from cache. The clickable
// check lives in Settings → Health.
function UpdateAvailablePill({ current }: { current?: string }) {
  const { latest } = useUpdateCheck();
  const hostOS = useHostOS();
  if (!isUpdateAvailable(current, latest)) return null;
  const href = `https://github.com/superbasedapp/observer/releases/tag/v${latest}`;
  return (
    <Tooltip
      content={
        <>
          Running v{current} - v{latest} is on npm. Click to view the release
          notes. Update with <kbd>{npmUpdateCommand(hostOS)}</kbd> or{" "}
          <kbd>pipx upgrade superbased-observer</kbd>, or run the new
          installer from superbased.app/download.
        </>
      }
    >
      <a
        href={href}
        target="_blank"
        rel="noreferrer"
        className="flex h-6 items-center gap-1.5 rounded-pill border border-accent/40 bg-accent-soft px-2 text-[10.5px] font-medium text-accent hover:bg-accent/20"
      >
        <Icon icon={ArrowUp} size={10} />
        v{latest} available
      </a>
    </Tooltip>
  );
}

// AccountControl is the top bar's account control (Getting started v2,
// lib/getStarted.ts topBarAccountView decides it): "Sign in" (or "Connect"
// once signed in) starts the same connect flow as the Overview Get started
// panel; while it waits it says so (the code is in the tooltip and on the
// panel); once connected it names where this machine is connected, linking
// to Settings > Account, plus an "Open online" button for the online
// dashboard. The address itself is never printed. On a phone the labels
// shrink to their icons.
function AccountControl() {
  const flow = useConnectFlow();
  const { account, enrolment } = useAccount(flow);
  const view = topBarAccountView({
    account,
    available: flow.available,
    progress: flow.progress,
    managed: !!enrolment?.enrolled && enrolment.tenancy === "managed",
  });
  switch (view.kind) {
    case "hidden":
      return null;
    case "connected":
      return (
        <span className="flex min-w-0 shrink items-center gap-1" data-tour="topbar-account">
          <Tooltip content={view.tooltip}>
            <RouterLink
              to="/settings?section=account"
              data-testid="account-chip"
              className={clsx(
                "flex h-6 min-w-0 max-w-[96px] items-center gap-1.5 rounded-pill border px-2 text-[10.5px] font-medium sm:max-w-[180px]",
                view.managed
                  ? "border-warn/40 bg-warn-soft text-warn hover:bg-warn/20"
                  : "border-success/30 bg-success-soft text-success hover:bg-success/20",
              )}
            >
              <LiveDot {...withDotClass(liveDotProps(CLOUD_SIGN_IN_DOT, "signed_in"), "h-1.5 w-1.5 shrink-0")} />
              <span className="truncate">{view.label}</span>
            </RouterLink>
          </Tooltip>
          {view.onlineUrl && (
            <Tooltip content="Open the online dashboard in a new tab">
              <a
                href={view.onlineUrl}
                target="_blank"
                rel="noreferrer noopener"
                data-testid="open-online"
                aria-label="Open online"
                className="flex h-6 shrink-0 items-center gap-1 rounded-2 border border-line-2 bg-bg-2 px-2 text-[10.5px] font-medium text-fg-2 hover:bg-bg-3 hover:text-fg-0"
              >
                <Icon icon={ExternalLink} size={11} />
                <span className="hidden sm:inline">Open online</span>
              </a>
            </Tooltip>
          )}
        </span>
      );
    case "connecting":
      return (
        <Tooltip content={view.tooltip}>
          <RouterLink
            to="/"
            data-tour="topbar-account"
            data-testid="account-connecting"
            aria-label={view.label}
            className="flex h-7 shrink-0 items-center gap-1.5 rounded-2 border border-info/30 bg-info-soft px-2 text-[11px] font-medium text-info"
          >
            <LiveDot {...withDotClass(liveDotProps(CLOUD_SIGN_IN_DOT, "signing_in"), "h-1.5 w-1.5 shrink-0")} />
            <span className="hidden sm:inline">{view.label}</span>
          </RouterLink>
        </Tooltip>
      );
    default:
      return (
        <Tooltip content={flow.error ?? view.tooltip}>
          <button
            type="button"
            data-tour="topbar-account"
            data-testid="account-sign-in"
            onClick={() => void flow.start()}
            disabled={flow.busy}
            aria-label={view.label}
            className="sb-press flex h-7 shrink-0 items-center gap-1.5 rounded-2 border border-accent/50 bg-accent-soft px-2.5 text-[11px] font-semibold text-accent hover:bg-accent/20 disabled:opacity-60"
          >
            <Icon icon={UserRound} size="xs" />
            <span className="hidden min-[400px]:inline">{view.label}</span>
          </button>
        </Tooltip>
      );
  }
}

// The pill's tone per state (lib/capturePill.ts decides the state).
const CAPTURE_PILL_TONE: Record<CapturePillState, string> = {
  active: "border-success/40 bg-success-soft text-success",
  paused: "border-warn/40 bg-warn-soft text-warn",
  absent: "border-line-2 bg-bg-2 text-fg-3",
};

function CaptureStatePill({ setup }: { setup: SetupClaude | null }) {
  const view = capturePillView(setup);
  if (view.hidden) return null;
  return (
    <Tooltip content={view.tooltip}>
      <span
        tabIndex={0}
        data-testid="capture-state-pill"
        data-state={view.state}
        className={clsx(
          "flex h-6 cursor-help items-center gap-1.5 rounded-pill border px-2 text-[10.5px] font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]",
          CAPTURE_PILL_TONE[view.state],
        )}
      >
        <LiveDot {...withDotClass(liveDotProps(CAPTURE_DOT, view.state), "h-1.5 w-1.5 shrink-0")} />
        {view.label}
      </span>
    </Tooltip>
  );
}

function IconButton({
  children,
  title,
  onClick,
}: {
  children: React.ReactNode;
  title: React.ReactNode;
  onClick: () => void;
}) {
  return (
    <Tooltip content={title}>
      <button
        type="button"
        onClick={onClick}
        className="grid h-7 w-7 place-items-center rounded-2 border border-line-2 bg-bg-2 text-fg-3 hover:bg-bg-3 hover:text-fg-0"
      >
        {children}
      </button>
    </Tooltip>
  );
}

// RefreshGlyph spins while any foreground request is in flight. A leaf so the
// busy/idle flip re-renders only this icon, not the TopBar.
function RefreshGlyph() {
  const busy = useApiActivity() > 0;
  return (
    <span className={busy ? "inline-flex animate-spin" : "inline-flex"} aria-hidden>
      <Icon icon={RefreshCw} size="xs" />
    </span>
  );
}

// YouChip is the avatar at the far right of the bar: initials from the best
// identity known (the org email, else the OS user) linking to the You page.
function YouChip() {
  const enrol = useApi<EnrolmentStatus>("/api/enrolment/status", undefined, [], { refreshMs: 30000 });
  const me = useApi<MeMachine>("/api/me/machine");
  const who = identityLabel(enrol.data?.enrolled ? enrol.data.user_email : undefined, me.data?.os_user);
  return (
    <Tooltip content={who ? `You: ${who}` : "You"}>
      <RouterLink
        to="/you"
        aria-label={who ? `You: ${who}` : "You"}
        className="grid h-7 w-7 shrink-0 place-items-center rounded-pill border border-line-2 bg-bg-2 text-[10.5px] font-semibold text-fg-1 hover:bg-bg-3 hover:text-fg-0"
      >
        {who ? avatarInitials(who) : "?"}
      </RouterLink>
    </Tooltip>
  );
}
