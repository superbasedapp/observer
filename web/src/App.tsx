import {
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { Sidebar } from "@/components/Sidebar";
import { TopBar } from "@/components/TopBar";
import { RestartPendingBanner } from "@/components/RestartPendingBanner";
import { IntegrityBanner } from "@/components/IntegrityBanner";
import { ManagedBanner } from "@/components/ManagedBanner";
import { DemoBanner } from "@/components/DemoBanner";
import { AnnouncementBanner } from "@/components/AnnouncementBanner";
import { SecurityOrgNotice } from "@/components/SecurityOrgNotice";
import { BudgetBanner } from "@/components/BudgetBanner";
import { CostDisplayBanner } from "@/components/CostDisplayBanner";
import { OrgIntelConsentBanner } from "@/components/OrgIntelConsentBanner";
import { BudgetWarningBanner } from "@/components/BudgetWarningBanner";
import { UpdateBanner } from "@/components/UpdateBanner";
import { FirstCaptureToast } from "@/components/FirstCaptureToast";
import { FirstRunHost } from "@/components/FirstRunHost";
import { ToastViewport } from "@/components/Toast";
import { MessageToast } from "@/components/MessageToast";
import { ConfigSavePreviewHost } from "@/components/ConfigSavePreviewHost";
import { KonamiEgg } from "@/components/KonamiEgg";
import { FilterBar } from "@/components/FilterBar";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { NotFoundPage } from "@/pages/NotFound";
import { NotInstalled } from "@/components/NotInstalled";
import { PAGE_ROUTES } from "@/lib/components.gen";
import { isComponentActive } from "@/lib/componentState";
import { useComponentState } from "@/lib/useComponents";
import { FilterProvider } from "@/lib/filters";
import { TourProvider } from "@/components/tour/TourProvider";
import { HelpInd } from "@/components/HelpInd";
import { HelpSlotProvider } from "@/components/primitives";
import {
  Button,
  ChartSkeleton,
  PageTransition,
  Skeleton,
  StatCardSkeleton,
  TopProgress,
} from "@shared/primitives";
import { useApiActivity } from "@/lib/useApi";
import { useRouteRider } from "@shared/lib/routeRider";
import { NAV_ITEMS } from "@/lib/nav";
import { reportToCostSearch } from "@/lib/nodePageTabs";
import {
  governedOrgLabel,
  isSectionHidden,
  isSectionReadOnly,
  useGovernance,
  useGovernanceVisibility,
  type Governance,
} from "@/lib/governance";
import { FLOOR_NAV_IDS, navSource, type GovernancePosture } from "@/lib/visibility";

// HelpDrawer carries the 164-entry registry — defer until first
// open so it doesn't bloat the shell chunk.
const HelpDrawer = lazy(() =>
  import("@/components/HelpDrawer").then((m) => ({ default: m.HelpDrawer })),
);
// The command palette (and framer-motion, which only it and the lazy pages
// use) loads on the first Cmd/Ctrl-K, keeping ~38 KB gzip of animation
// library off the first paint.
const CommandPalette = lazy(() =>
  import("@/components/CommandPalette").then((m) => ({
    default: m.CommandPalette,
  })),
);

// Every routed page is lazy and imported ONLY by the generated registry
// (lib/components.gen.ts, modular packaging plan 5.1 rev N5): a per-distro
// build regenerates it without the pages of absent components, so their
// chunks never ship. lib/componentRegistry.test.ts is the lint rule.
// navIdForPath maps the current pathname onto its NAV_ITEMS id (exact
// match — every route in AnimatedRoutes has a 1:1 NAV_ITEMS entry; a
// redirect-only route like /report returns null and is therefore never
// governed-hidden).
function navIdForPath(pathname: string): string | null {
  return NAV_ITEMS.find((it) => it.path === pathname)?.id ?? null;
}

// componentForPath maps the current pathname onto the component that owns
// its page (the generated registry), or undefined for a path no page owns.
function componentForPath(pathname: string): string | undefined {
  const rel = pathname.replace(/^\/+/, "").replace(/\/+$/, "");
  return PAGE_ROUTES.find((r) => r.path === rel)?.component;
}

// ManagedNotice renders instead of the page when the current route is
// hidden on this machine (the resolved visibility: the org's directives plus
// the managed-node defaults) - a direct-URL visit to a hidden page must say
// so, not blank out or 404.
function ManagedNotice({ gov, navId }: { gov: Governance | null; navId: string }) {
  const notice = gov?.notice;
  const byDefault = navSource(gov, navId) === "default";
  return (
    <div className="flex h-full items-center justify-center p-12" data-testid="managed-notice">
      <div className="max-w-md text-center">
        <h2 className="text-[15px] font-semibold text-fg-1">
          Managed by your organization
        </h2>
        <p className="mt-2 text-[12.5px] text-fg-3">
          This page is managed by {governedOrgLabel(gov)} and is not available on
          this machine.
          {byDefault &&
            " It is hidden by default on organization-managed machines; your administrator can make it available."}
        </p>
        {(notice?.contact || notice?.policy_url) && (
          <p className="mt-3 text-[11.5px] text-fg-3">
            {notice?.contact && (
              <a
                href={`mailto:${notice.contact}`}
                className="text-accent hover:underline"
              >
                {notice.contact}
              </a>
            )}
            {notice?.contact && notice?.policy_url && " · "}
            {notice?.policy_url && (
              <a
                href={notice.policy_url}
                target="_blank"
                rel="noreferrer"
                className="text-accent hover:underline"
              >
                {notice.policy_url}
              </a>
            )}
          </p>
        )}
      </div>
    </div>
  );
}

// PostureUnresolved renders instead of a governed page until this machine's
// visibility posture is known (Sol A4-05). While the first read is in flight
// it is a quiet placeholder; when the read failed it says so and offers a
// retry, rather than assuming nothing is hidden. Settings and Privacy (the
// floor) never wait on it.
function PostureUnresolved({
  posture,
  onRetry,
}: {
  posture: GovernancePosture;
  onRetry: () => void;
}) {
  if (posture === "pending") {
    return (
      <div className="flex h-full items-center justify-center p-12" data-testid="posture-pending">
        <p className="text-[12.5px] text-fg-3">Checking which pages are available on this machine...</p>
      </div>
    );
  }
  return (
    <div className="flex h-full items-center justify-center p-12" data-testid="posture-unavailable">
      <div className="max-w-md text-center">
        <h2 className="text-[15px] font-semibold text-fg-1">Page unavailable</h2>
        <p className="mt-2 text-[12.5px] text-fg-3">
          The dashboard could not read which pages are available on this machine, so it is not
          showing this one. Settings and Privacy stay available.
        </p>
        <Button size="sm" className="mt-3" onClick={onRetry}>
          Try again
        </Button>
      </div>
    </div>
  );
}

// ManagedReadOnlyBar sits above a page this machine's organization locked
// read-only: the page renders, and its writes are refused by the daemon
// (409 governance_read_only). Saying so up front beats a button that fails.
function ManagedReadOnlyBar({ gov }: { gov: Governance | null }) {
  return (
    <div
      role="status"
      data-testid="managed-read-only"
      className="border-b border-line-1 bg-bg-1 px-4 py-2 text-[11.5px] text-fg-3 sm:px-6"
    >
      Read-only on this machine: {governedOrgLabel(gov)} manages this page. You can see
      everything here, but changes are turned off.
    </div>
  );
}

// ReportRedirect retires the standalone /report page (platform tabs plan §3
// row 9): the monthly statement is the Cost page's Statement tab now, and an
// old `/report?month=&project=` link lands there with every param kept.
function ReportRedirect() {
  const { search } = useLocation();
  return <Navigate to={`/cost${reportToCostSearch(search)}`} replace />;
}

// RouteErrorBoundary keys the boundary on the pathname so navigating
// to another tab after a crash gives that tab a clean mount.
function RouteErrorBoundary({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();
  return <ErrorBoundary key={pathname}>{children}</ErrorBoundary>;
}

// RouteFallback is shaped like a page (header, KPI strip, chart) so a lazy
// route's chunk load reads as the page arriving, not as a spinner swap.
function RouteFallback() {
  return (
    <div
      className="flex flex-col gap-5 p-4 sm:p-6"
      role="status"
      aria-label="Loading page"
    >
      <div className="flex flex-col gap-2">
        <Skeleton className="h-5 w-48" />
        <Skeleton className="h-3 w-80 max-w-full" />
      </div>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <StatCardSkeleton />
        <StatCardSkeleton />
        <StatCardSkeleton />
        <StatCardSkeleton />
      </div>
      <div className="rounded-3 border border-line-2 bg-bg-2 p-4">
        <ChartSkeleton height={220} />
      </div>
    </div>
  );
}

// A route change plays the shared CSS page-enter (fade + 6px rise, transform
// and opacity only). There is no exit phase: the old AnimatePresence
// mode="wait" held every navigation back ~140 ms while the outgoing page
// faded. Suspense sits INSIDE the transition so a lazy chunk's skeleton
// enters the same way the page does.
// DOCK_CLEARED_PAGE is the page box: its height leaves the dock's
// clearance free, and an ::after spacer of the same height follows the page
// content wherever that content ends. 0 when no dock is on screen.
const DOCK_CLEARED_PAGE =
  "h-[calc(100%-var(--sb-dock-clearance,0px))] after:block after:h-[var(--sb-dock-clearance,0px)] after:content-['']";

function AnimatedRoutes() {
  const location = useLocation();
  return (
    // The floating terminal dock's clearance (T-855, lib/dockClearance) is
    // taken off the page height and added back as a spacer AFTER the page,
    // so a full-height page (Messages) ends above the dock and a long page
    // that overflows this box still scrolls its last row clear of the dock
    // (padding on the scroller alone stops at this box, not at its overflow).
    <PageTransition routeKey={location.pathname} className={DOCK_CLEARED_PAGE}>
      <Suspense fallback={<RouteFallback />}>
        <Routes location={location}>
          {PAGE_ROUTES.map((r) =>
            r.path === "" ? (
              <Route key="index" index element={<r.Page />} />
            ) : (
              <Route key={r.path} path={r.path} element={<r.Page />} />
            ),
          )}
          <Route path="report" element={<ReportRedirect />} />
          {/* D-6: an unknown route gets an honest page instead of a
              silent redirect that reads as a navigation bug. */}
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </Suspense>
    </PageTransition>
  );
}

// Leaf reader of the query cache's foreground activity. Keep it a leaf: the
// shell re-rendering on every busy/idle flip would re-render the whole app.
// Foreground requests in flight (a filter change, a page's first load)
// drive the thin gradient bar along the top of the content column.
// D-665..D-669: Obs rides the line only during a slow ROUTE load (useRouteRider:
// from navigation until that page's own requests settle), never for a later
// filter change, refetch or poll.
function ActivityProgress() {
  const { pathname } = useLocation();
  const active = useApiActivity() > 0;
  const rider = useRouteRider(pathname, active);
  return <TopProgress active={active} rider={rider} className="z-40" />;
}

// Renderer injected into the shared design-system help slot: DS components
// (StatCard/HeroStat/PageHeader) render this app's HelpInd for their helpId,
// which the delegated data-help-id click handler below turns into a drawer.
const renderHelpInd = (id: string) => <HelpInd id={id} />;

export default function App() {
  const [helpOpen, setHelpOpen] = useState(false);
  const [helpId, setHelpId] = useState<string | null>(null);
  // Mobile nav drawer (< lg). The sidebar is a static sibling on
  // desktop and an overlay drawer on small screens; this drives it.
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const { pathname } = useLocation();
  // Governed-node route guard: a direct-URL visit to a page this
  // machine's organization hid must render an honest notice, not a
  // blank page or a 404. No-op on a solo node (gov.data is
  // {active: false, ...} or null, and isSectionHidden treats both as
  // "nothing hidden").
  const gov = useGovernance();
  // Until the posture is known the guard fails CLOSED (Sol A4-05): a governed
  // route renders PostureUnresolved, never the page.
  const visibility = useGovernanceVisibility();
  const routeNavId = navIdForPath(pathname) ?? "";
  const routeUnresolved =
    visibility.posture !== "ready" && routeNavId !== "" && !FLOOR_NAV_IDS.includes(routeNavId);
  const routeHidden = !routeUnresolved && isSectionHidden(visibility.gov, routeNavId);
  const routeReadOnly =
    !routeUnresolved && !routeHidden && isSectionReadOnly(visibility.gov, routeNavId);
  // Component route guard (modular packaging plan 7.3): a page whose
  // component is not active on this machine renders NotInstalled, never a
  // blank page or a wall of failed reads. Fails open: until the state read
  // lands, or when it fails, every page renders as before.
  const compState = useComponentState();
  const routeComponent = componentForPath(pathname);
  const routeNotInstalled =
    !routeUnresolved && !routeHidden && !isComponentActive(compState.data?.view, routeComponent);
  // Close the drawer whenever the route changes (nav tap, command
  // palette, back button) so it never lingers over the new page.
  useEffect(() => {
    setMobileNavOpen(false);
  }, [pathname]);
  // Once opened, keep the drawer mounted so subsequent ? presses
  // are instant. First open pays the chunk-fetch cost.
  const [helpEverOpened, setHelpEverOpened] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [paletteEverOpened, setPaletteEverOpened] = useState(false);
  useEffect(() => {
    if (helpOpen && !helpEverOpened) setHelpEverOpened(true);
  }, [helpOpen, helpEverOpened]);
  useEffect(() => {
    if (paletteOpen && !paletteEverOpened) setPaletteEverOpened(true);
  }, [paletteOpen, paletteEverOpened]);


  // Keyboard shortcuts global to the app shell. `?` toggles help when
  // no input is focused; ⌘K / Ctrl-K toggles the command palette
  // (works even when a field is focused — matches VSCode/Linear).
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const t = e.target as HTMLElement | null;
      const tag = (t?.tagName || "").toLowerCase();
      const isInput =
        tag === "input" || tag === "textarea" || t?.isContentEditable;
      if ((e.key === "k" || e.key === "K") && (e.metaKey || e.ctrlKey)) {
        // Let an embedded terminal keep Ctrl/Cmd-K — a TUI (and its own
        // custom key handler) owns the combo when focus is inside the xterm.
        if (t?.closest?.(".xterm")) return;
        e.preventDefault();
        setPaletteOpen((o) => !o);
        return;
      }
      if (isInput) return;
      if (e.key === "?") {
        e.preventDefault();
        setHelpOpen((o) => !o);
      }
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  // Clicking any HelpInd (data-help-id) opens the drawer scrolled to
  // that entry. One delegated listener keeps the indicator
  // lightweight and avoids prop-drilling.
  useEffect(() => {
    function onClick(e: MouseEvent) {
      const el = (e.target as HTMLElement | null)?.closest<HTMLElement>(
        "[data-help-id]",
      );
      if (!el) return;
      const id = el.getAttribute("data-help-id");
      if (id) {
        setHelpId(id);
        setHelpOpen(true);
      }
    }
    document.addEventListener("click", onClick);
    return () => document.removeEventListener("click", onClick);
  }, []);

  const openHelp = useCallback(() => setHelpOpen(true), []);

  return (
    <HelpSlotProvider value={renderHelpInd}>
    <TourProvider>
      <FilterProvider>
        <div className="flex h-full w-full bg-bg-0 text-fg-1">
          <Sidebar
            open={mobileNavOpen}
            onClose={() => setMobileNavOpen(false)}
          />
          {/* bg-bg-0 (the shell's own colour) so the column stays opaque while
              it slides over the rail during the nav-collapse FLIP (Sidebar). */}
          <main className="relative flex min-w-0 flex-1 flex-col bg-bg-0">
            <ActivityProgress />
            <TopBar onHelp={openHelp} onMenu={() => setMobileNavOpen(true)} />
            <RestartPendingBanner />
            <IntegrityBanner />
            <ManagedBanner gov={gov.data} />
            <DemoBanner />
            <AnnouncementBanner />
            <SecurityOrgNotice />
            <CostDisplayBanner />
            {/* Cloud Intelligence parity (design 3.7): an individual machine whose
                org made Cloud Intelligence a condition of membership sees
                Accept / Leave on every page until it chooses. */}
            <OrgIntelConsentBanner />
            {/* Enterprise update management (W5): what the ORG has said about
                this node's version, as opposed to the npm pill in the TopBar
                which asks the public registry on a click. One loopback GET on
                mount, no polling. */}
            <UpdateBanner />
            <BudgetBanner />
            {/* The ORG's budgets for this developer (GET /api/budget/status,
                15 s poll). In the shell, above the routes, so it shows on
                every page - Terminals included - and toasts a new notice
                once per browser through the ToastViewport below. */}
            <BudgetWarningBanner />
            <FirstCaptureToast />
            {/* The first-run capture view (T-922): detected AI tools and the
                watcher's progress over their existing history. Opens by
                itself once on a fresh install; reopened from the command
                palette or Settings, Connected tools. */}
            <FirstRunHost />
            <ToastViewport />
            {/* An admin message arriving while the dashboard is open (T-854):
                one toast with Open and Reply, when the developer kept the
                toast surface on. */}
            <MessageToast />
            {/* The one preview every config section save opens before it
                writes (T-432, lib/configSectionSave.ts). */}
            <ConfigSavePreviewHost />
            <KonamiEgg />
            <FilterBar onOpenPalette={() => setPaletteOpen(true)} />
            {/* The page area. The floating terminal dock's clearance is
                reserved by the page box itself (AnimatedRoutes,
                DOCK_CLEARED_PAGE), so no page puts a row, a card or a Send
                button under the dock once scrolled to its end (T-803,
                T-855). */}
            <div className="min-h-0 flex-1 overflow-y-auto">
              {routeReadOnly && <ManagedReadOnlyBar gov={gov.data} />}
              {routeUnresolved ? (
                <PostureUnresolved posture={visibility.posture} onRetry={visibility.reload} />
              ) : routeHidden ? (
                <ManagedNotice gov={gov.data} navId={routeNavId} />
              ) : routeNotInstalled && routeComponent ? (
                <NotInstalled
                  component={routeComponent}
                  state={compState.data?.view.components.find((c) => c.id === routeComponent)?.state}
                />
              ) : (
                /* D-6: the boundary sits below the shell so a crashing
                   page can't take the sidebar/topbar with it; keying on
                   pathname resets it when the user navigates away. */
                <RouteErrorBoundary>
                  <AnimatedRoutes />
                </RouteErrorBoundary>
              )}
            </div>
          </main>
          {helpEverOpened && (
            <Suspense fallback={null}>
              <HelpDrawer
                open={helpOpen}
                onClose={() => setHelpOpen(false)}
                initialId={helpId}
              />
            </Suspense>
          )}
          {paletteEverOpened && (
            <Suspense fallback={null}>
              <CommandPalette
                open={paletteOpen}
                onClose={() => setPaletteOpen(false)}
              />
            </Suspense>
          )}
        </div>
      </FilterProvider>
    </TourProvider>
    </HelpSlotProvider>
  );
}
