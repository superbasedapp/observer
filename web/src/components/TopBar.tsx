import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import clsx from "clsx";
import { NAV_GROUPS } from "@/lib/nav";
import { useApi } from "@/lib/useApi";
import { fmtDuration } from "@/lib/format";
import { useTheme, type ThemeMode } from "@/lib/theme";
import type { CloudStatusResponse, EnrolmentStatus, SetupClaude, StatusSnapshot } from "@/lib/types";
import { isUpdateAvailable, useUpdateCheck } from "@/lib/version";
import { Tooltip } from "@/components/primitives";
import { InstanceSwitcher } from "@/components/InstanceSwitcher";

// `dashboard-refresh` is a window-level CustomEvent that useApi
// listens for to re-fire its fetch. TopBar's Refresh button is the
// only emitter for now; later we may add a per-window-blur retry.
export const REFRESH_EVENT = "dashboard-refresh";

// Maps the current pathname to the primary data endpoint that
// Export will download. Falls back to /api/status.
const EXPORT_MAP: Record<string, string> = {
  "/": "/api/status",
  "/sessions": "/api/sessions?limit=200",
  "/actions": "/api/actions?limit=500",
  "/cost": "/api/models",
  "/analysis": "/api/analysis/headline",
  "/tools": "/api/tools",
  "/compression": "/api/compression/events?limit=500",
  "/discovery": "/api/discover",
  "/patterns": "/api/patterns?limit=200",
  "/settings": "/api/config",
};

export function TopBar({
  onHelp,
  onMenu,
}: {
  onHelp?: () => void;
  // onMenu opens the mobile nav drawer (< lg). Renders a hamburger.
  onMenu?: () => void;
}) {
  const { pathname } = useLocation();
  const group = NAV_GROUPS.find((g) =>
    g.items.some((i) => i.path === pathname),
  );
  const item = group?.items.find((i) => i.path === pathname);
  // Live-capture refresh: 5s on the lightweight status surface so the
  // header's "last seen" and counters stay current. Setup config is
  // static; no refresh.
  const status = useApi<StatusSnapshot>("/api/status", undefined, [], { refreshMs: 5000 });
  const setup = useApi<SetupClaude>("/api/setup/claude");
  const lastSeen = status.data?.last_action_at;

  function refresh() {
    window.dispatchEvent(new CustomEvent(REFRESH_EVENT));
  }

  async function exportCurrent() {
    const endpoint = EXPORT_MAP[pathname] ?? "/api/status";
    try {
      const res = await fetch(endpoint);
      const blob = await res.blob();
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
      console.error("export failed", e);
    }
  }

  return (
    <header className="flex h-[var(--header-h)] items-center justify-between gap-3 border-b border-line-1 bg-bg-1 px-3 sm:px-5">
      <div className="flex min-w-0 items-center gap-2 text-[12px] text-fg-3">
        {onMenu && (
          <button
            type="button"
            onClick={onMenu}
            aria-label="Open navigation"
            className="grid h-7 w-7 shrink-0 place-items-center rounded-2 border border-line-2 bg-bg-2 text-fg-2 hover:bg-bg-3 hover:text-fg-0 lg:hidden"
          >
            <MenuIcon />
          </button>
        )}
        {group && (
          <div className="flex min-w-0 items-center gap-2">
            <span className="hidden sm:inline">{group.label}</span>
            <span className="hidden sm:inline">/</span>
            <b className="truncate text-fg-1">{item?.label ?? "-"}</b>
          </div>
        )}
      </div>
      <div className="flex items-center gap-2 text-[11px] text-fg-3">
        {/* Secondary status + Export — hidden on phones (< md) to keep
            the header uncluttered; the drawer + Refresh stay reachable. */}
        <div className="hidden items-center gap-2 md:flex">
          <LastActivity iso={lastSeen} />
          <UpdateAvailablePill current={status.data?.version} />
          <EnrolmentBadge />
          <CloudAccountBadge />
          <CaptureStatePill setup={setup.data} />
          {/* Instance switcher — renders nothing unless the operator has
              configured [[terminal.ssh.profiles]], so a solo install's header
              is unchanged. */}
          <InstanceSwitcher />
          <div className="mx-1 h-4 w-px bg-line-2" />
          <Tooltip content="Export the current page's data as JSON">
            <button
              type="button"
              onClick={exportCurrent}
              className="flex h-7 items-center gap-1.5 rounded-2 border border-line-2 bg-bg-2 px-2.5 text-[11px] text-fg-2 hover:bg-bg-3 hover:text-fg-0"
            >
              <DownloadIcon />
              Export
            </button>
          </Tooltip>
        </div>
        <Tooltip content="Reload data on every visible card">
          <button
            type="button"
            onClick={refresh}
            className="flex h-7 items-center gap-1.5 rounded-2 bg-accent px-2.5 text-[11px] font-semibold text-accent-on hover:bg-accent-strong"
          >
            <RefreshIcon />
            <span className="hidden sm:inline">Refresh</span>
          </button>
        </Tooltip>
        {/* Extra link tools — desktop only (low value on a phone). */}
        <div className="hidden items-center gap-2 md:flex">
          <div className="mx-1 h-4 w-px bg-line-2" />
          <IconButton
            title="Open in new tab"
            onClick={() => window.open(window.location.href, "_blank")}
          >
            <NewTabIcon />
          </IconButton>
          <IconButton
            title="Copy link"
            onClick={() => {
              void navigator.clipboard?.writeText(window.location.href);
            }}
          >
            <LinkIcon />
          </IconButton>
        </div>
        <ThemeToggle />
        {onHelp && (
          <span data-tour="topbar-help" className="inline-flex">
            <IconButton
              title={<>Help <kbd>?</kbd></>}
              onClick={onHelp}
            >
              <span className="text-[12px] font-semibold">?</span>
            </IconButton>
          </span>
        )}
      </div>
    </header>
  );
}

// Tri-state Light / Dark / System toggle. Renders as a tight three-
// button segmented control. Reads/writes via useTheme().
function ThemeToggle() {
  const { mode, setMode } = useTheme();
  const opts: { value: ThemeMode; label: ReactSVG; title: string }[] = [
    { value: "light", label: <SunIcon />, title: "Light theme" },
    { value: "dark", label: <MoonIcon />, title: "Dark theme" },
    { value: "system", label: <MonitorIcon />, title: "Follow system" },
  ];
  return (
    <div
      role="radiogroup"
      aria-label="Theme"
      data-tour="topbar-theme"
      className="flex items-center gap-0.5 rounded-2 border border-line-2 bg-bg-2 p-0.5"
    >
      {opts.map((o) => (
        <Tooltip key={o.value} content={o.title}>
          <button
            type="button"
            role="radio"
            aria-checked={mode === o.value}
            onClick={() => setMode(o.value)}
            className={clsx(
              "grid h-6 w-6 place-items-center rounded-1 transition-colors",
              mode === o.value
                ? "bg-bg-4 text-fg-0"
                : "text-fg-3 hover:bg-bg-3 hover:text-fg-1",
            )}
          >
            {o.label}
          </button>
        </Tooltip>
      ))}
    </div>
  );
}

type ReactSVG = React.ReactElement;

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
      <span
        className={clsx(
          "h-1.5 w-1.5 rounded-full",
          fresh ? "bg-success" : "bg-fg-4",
        )}
      />
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
  if (!isUpdateAvailable(current, latest)) return null;
  const href = `https://github.com/superbasedapp/observer/releases/tag/v${latest}`;
  return (
    <Tooltip
      content={
        <>
          Running v{current} - v{latest} is on npm. Click to view the release
          notes. Update with <kbd>npm i -g @superbased/observer</kbd> or{" "}
          <kbd>pipx upgrade superbased-observer</kbd>.
        </>
      }
    >
      <a
        href={href}
        target="_blank"
        rel="noreferrer"
        className="flex h-6 items-center gap-1.5 rounded-pill border border-accent/40 bg-accent-soft px-2 text-[10.5px] font-medium text-accent hover:bg-accent/20"
      >
        <UpArrowIcon />
        v{latest} available
      </a>
    </Tooltip>
  );
}

function UpArrowIcon() {
  return (
    <svg width="9" height="9" viewBox="0 0 12 12" fill="none" aria-hidden>
      <path
        d="M6 10V2m0 0L3 5m3-3 3 3"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

// EnrolmentBadge shows "Enrolled in <Org>" when this agent is enrolled in a
// Teams org, linking to the Settings → Enrolment page. It renders nothing when
// not enrolled (or org mode is off), so a solo-local install's header is
// byte-identical to a non-org build.
function EnrolmentBadge() {
  const status = useApi<EnrolmentStatus>("/api/enrolment/status", undefined, [], {
    refreshMs: 30000,
  });
  if (!status.data?.enrolled) return null;
  const org = status.data.org_name || status.data.org_id || "organisation";
  return (
    <Tooltip content={`Sharing content-free activity rollups with ${org}. Manage in Settings → Enrolment.`}>
      <a
        href="/settings"
        className="flex h-6 items-center gap-1.5 rounded-pill border border-accent/40 bg-accent-soft px-2 text-[10.5px] font-medium text-accent hover:bg-accent/20"
      >
        <span className="h-1.5 w-1.5 rounded-full bg-accent" />
        Enrolled in {org}
      </a>
    </Tooltip>
  );
}

// CloudAccountBadge is the compact "Cloud: signed in / not signed in"
// indicator beside the enrolment chip, linking to Settings → Cloud
// Intelligence where the Sign in button lives. It renders nothing when the
// dashboard has no cloud-account seam wired (`sign_in` absent — an embedder
// without `observer start`), so such a header stays byte-identical. The
// state is a LOCAL keychain read the daemon does on our behalf; it never
// reflects hosted-service state.
function CloudAccountBadge() {
  const status = useApi<CloudStatusResponse>("/api/cloud/status", undefined, [], {
    refreshMs: 30000,
  });
  const si = status.data?.sign_in;
  if (!si) return null;
  const signingIn = si.login_running;
  const signedIn = si.known && si.signed_in;
  const label = signingIn ? "Cloud: signing in…" : signedIn ? "Cloud: signed in" : "Cloud: not signed in";
  const tip = signedIn
    ? "A device-bound cloud credential is stored on this machine. Manage in Settings → Cloud Intelligence."
    : "Optional cloud enrichment is off until you sign in. Sign in from Settings → Cloud Intelligence.";
  return (
    <Tooltip content={tip}>
      <a
        href="/settings?section=cloud"
        className={
          "flex h-6 items-center gap-1.5 rounded-pill border px-2 text-[10.5px] font-medium " +
          (signedIn
            ? "border-success/30 bg-success-soft text-success hover:bg-success/20"
            : "border-line-2 bg-bg-2 text-fg-3 hover:bg-bg-3")
        }
      >
        <span className={"h-1.5 w-1.5 rounded-full " + (signedIn ? "bg-success" : signingIn ? "bg-info" : "bg-fg-4")} />
        {label}
      </a>
    </Tooltip>
  );
}

function CaptureStatePill({ setup }: { setup: SetupClaude | null }) {
  const active =
    setup?.status === "oauth_ready" || setup?.status === "api_key_ready";
  return (
    <Tooltip
      content={
        active
          ? "Proxy active - capturing"
          : `Proxy ${setup?.status ?? "unknown"}`
      }
    >
      <span
        tabIndex={0}
        className={clsx(
          "flex h-6 cursor-help items-center gap-1.5 rounded-pill border px-2 text-[10.5px] font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]",
          active
            ? "border-success/40 bg-success-soft text-success"
            : "border-warn/40 bg-warn-soft text-warn",
        )}
      >
        <span
          className={clsx(
            "h-1.5 w-1.5 rounded-full",
            active ? "bg-success" : "bg-warn",
          )}
        />
        {active ? "Active" : "Paused"}
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

// --- icons (inline so we don't take a deps hit) -----------------------

function MenuIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 16 16" fill="none" aria-hidden>
      <path
        d="M2.5 4h11M2.5 8h11M2.5 12h11"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
    </svg>
  );
}

function DownloadIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 16 16" fill="none">
      <path
        d="M8 2v8m0 0L5 7m3 3 3-3M3 13h10"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function RefreshIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 16 16" fill="none">
      <path
        d="M3 8a5 5 0 0 1 8.5-3.5L13 6m0-3v3h-3m3 2a5 5 0 0 1-8.5 3.5L3 10m0 3v-3h3"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function NewTabIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 16 16" fill="none">
      <path
        d="M6 3H3v10h10v-3M9 3h4v4M13 3 7 9"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function LinkIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 16 16" fill="none">
      <path
        d="M6.5 9.5 9.5 6.5M7 4.5l1.5-1.5a2.5 2.5 0 1 1 3.5 3.5L10.5 8M9 11.5 7.5 13a2.5 2.5 0 1 1-3.5-3.5L5.5 8"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function SunIcon() {
  return (
    <svg width="11" height="11" viewBox="0 0 16 16" fill="none">
      <circle cx="8" cy="8" r="3" stroke="currentColor" strokeWidth="1.4" />
      <path
        d="M8 1.5v1.5M8 13v1.5M1.5 8H3M13 8h1.5M3.3 3.3l1 1M11.7 11.7l1 1M3.3 12.7l1-1M11.7 4.3l1-1"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
      />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg width="11" height="11" viewBox="0 0 16 16" fill="none">
      <path
        d="M13 9.5A5 5 0 0 1 6.5 3a5 5 0 1 0 6.5 6.5Z"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function MonitorIcon() {
  return (
    <svg width="11" height="11" viewBox="0 0 16 16" fill="none">
      <rect
        x="2"
        y="3"
        width="12"
        height="8"
        rx="1.2"
        stroke="currentColor"
        strokeWidth="1.4"
      />
      <path
        d="M6 13.5h4M8 11v2.5"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
      />
    </svg>
  );
}
