import {
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { Route, Routes, useLocation } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";
import { Sidebar } from "@/components/Sidebar";
import { TopBar } from "@/components/TopBar";
import { RestartPendingBanner } from "@/components/RestartPendingBanner";
import { IntegrityBanner } from "@/components/IntegrityBanner";
import { ManagedBanner } from "@/components/ManagedBanner";
import { DemoBanner } from "@/components/DemoBanner";
import { AnnouncementBanner } from "@/components/AnnouncementBanner";
import { BudgetBanner } from "@/components/BudgetBanner";
import { UpdateBanner } from "@/components/UpdateBanner";
import { FirstCaptureToast } from "@/components/FirstCaptureToast";
import { ToastViewport } from "@/components/Toast";
import { KonamiEgg } from "@/components/KonamiEgg";
import { FilterBar } from "@/components/FilterBar";
import { CommandPalette } from "@/components/CommandPalette";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { NotFoundPage } from "@/pages/NotFound";
import { FilterProvider } from "@/lib/filters";
import { TourProvider } from "@/components/tour/TourProvider";
import { HelpInd } from "@/components/HelpInd";
import { HelpSlotProvider } from "@/components/primitives";
import { NAV_ITEMS } from "@/lib/nav";
import { isSectionHidden, useGovernance, type Governance } from "@/lib/governance";

// HelpDrawer carries the 164-entry registry — defer until first
// open so it doesn't bloat the shell chunk.
const HelpDrawer = lazy(() =>
  import("@/components/HelpDrawer").then((m) => ({ default: m.HelpDrawer })),
);

// Lazy per-route — keeps recharts/tanstack-table chunks off the
// critical path. Pages export named components, so each import
// re-maps the named export onto `default` for React.lazy.
const OverviewPage = lazy(() =>
  import("@/pages/Overview").then((m) => ({ default: m.OverviewPage })),
);
const CostPage = lazy(() =>
  import("@/pages/Cost").then((m) => ({ default: m.CostPage })),
);
const AnalysisPage = lazy(() =>
  import("@/pages/Analysis").then((m) => ({ default: m.AnalysisPage })),
);
const SessionsPage = lazy(() =>
  import("@/pages/Sessions").then((m) => ({ default: m.SessionsPage })),
);
const LivePage = lazy(() =>
  import("@/pages/Live").then((m) => ({ default: m.LivePage })),
);
const SearchPage = lazy(() =>
  import("@/pages/Search").then((m) => ({ default: m.SearchPage })),
);
const ActionsPage = lazy(() =>
  import("@/pages/Actions").then((m) => ({ default: m.ActionsPage })),
);
const ProjectsPage = lazy(() =>
  import("@/pages/Projects").then((m) => ({ default: m.ProjectsPage })),
);
const ToolsPage = lazy(() =>
  import("@/pages/Tools").then((m) => ({ default: m.ToolsPage })),
);
const CompressionPage = lazy(() =>
  import("@/pages/Compression").then((m) => ({ default: m.CompressionPage })),
);
const CachePage = lazy(() =>
  import("@/pages/Cache").then((m) => ({ default: m.CachePage })),
);
const DiscoveryPage = lazy(() =>
  import("@/pages/Discovery").then((m) => ({ default: m.DiscoveryPage })),
);
const SuggestionsPage = lazy(() =>
  import("@/pages/Suggestions").then((m) => ({ default: m.SuggestionsPage })),
);
const PatternsPage = lazy(() =>
  import("@/pages/Patterns").then((m) => ({ default: m.PatternsPage })),
);
const RoutingPage = lazy(() =>
  import("@/pages/Routing").then((m) => ({ default: m.RoutingPage })),
);
const BenchmarksPage = lazy(() =>
  import("@/pages/Benchmarks").then((m) => ({ default: m.BenchmarksPage })),
);
const SettingsPage = lazy(() =>
  import("@/pages/Settings").then((m) => ({ default: m.SettingsPage })),
);
const RemotePage = lazy(() =>
  import("@/pages/Remote").then((m) => ({ default: m.RemotePage })),
);
const TerminalsPage = lazy(() =>
  import("@/pages/Terminals").then((m) => ({ default: m.TerminalsPage })),
);
const SecurityPage = lazy(() =>
  import("@/pages/Security").then((m) => ({ default: m.SecurityPage })),
);
const EgressPage = lazy(() =>
  import("@/pages/Egress").then((m) => ({ default: m.EgressPage })),
);
const PoliciesPage = lazy(() =>
  import("@/pages/Policies").then((m) => ({ default: m.PoliciesPage })),
);
const PrivacyPage = lazy(() =>
  import("@/pages/Privacy").then((m) => ({ default: m.PrivacyPage })),
);
const ReportPage = lazy(() =>
  import("@/pages/Report").then((m) => ({ default: m.ReportPage })),
);

// navIdForPath maps the current pathname onto its NAV_ITEMS id (exact
// match — every route in AnimatedRoutes has a 1:1 NAV_ITEMS entry
// except a handful of non-nav routes like /report, which return null
// and are therefore never governed-hidden).
function navIdForPath(pathname: string): string | null {
  return NAV_ITEMS.find((it) => it.path === pathname)?.id ?? null;
}

// ManagedNotice renders instead of the page when the current route is
// in the resolved governance posture's hidden_sections — a direct-URL
// visit to a hidden page must say so, not blank out or 404.
function ManagedNotice({ gov }: { gov: Governance | null }) {
  const notice = gov?.notice;
  return (
    <div className="flex h-full items-center justify-center p-12">
      <div className="max-w-md text-center">
        <h2 className="text-[15px] font-semibold text-fg-1">
          Managed by your organization
        </h2>
        <p className="mt-2 text-[12.5px] text-fg-3">
          This page is managed by your organization and is not available on
          this machine.
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

// RouteErrorBoundary keys the boundary on the pathname so navigating
// to another tab after a crash gives that tab a clean mount.
function RouteErrorBoundary({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();
  return <ErrorBoundary key={pathname}>{children}</ErrorBoundary>;
}

function RouteFallback() {
  return (
    <div className="flex h-full items-center justify-center p-12">
      <div className="flex items-center gap-3 text-[12px] text-fg-3">
        <span className="inline-block h-3 w-3 animate-spin rounded-full border border-line-3 border-t-accent" />
        Loading…
      </div>
    </div>
  );
}

// AnimatePresence keyed on pathname so a route change crossfades
// instead of snapping. mode="wait" lets the outgoing page fade
// out before the incoming page mounts — avoids stacked layouts
// during the swap.
function AnimatedRoutes() {
  const location = useLocation();
  return (
    <AnimatePresence mode="wait" initial={false}>
      <motion.div
        key={location.pathname}
        initial={{ opacity: 0, y: 4 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -2 }}
        transition={{ duration: 0.14, ease: "easeOut" }}
        className="h-full"
      >
        <Routes location={location}>
          <Route index element={<OverviewPage />} />
          <Route path="live" element={<LivePage />} />
          <Route path="search" element={<SearchPage />} />
          <Route path="cost" element={<CostPage />} />
          <Route path="report" element={<ReportPage />} />
          <Route path="analysis" element={<AnalysisPage />} />
          <Route path="sessions" element={<SessionsPage />} />
          <Route path="actions" element={<ActionsPage />} />
          <Route path="projects" element={<ProjectsPage />} />
          <Route path="security" element={<SecurityPage />} />
          <Route path="egress" element={<EgressPage />} />
          <Route path="policies" element={<PoliciesPage />} />
          <Route path="tools" element={<ToolsPage />} />
          <Route path="compression" element={<CompressionPage />} />
          <Route path="cache" element={<CachePage />} />
          <Route path="suggestions" element={<SuggestionsPage />} />
          <Route path="routing" element={<RoutingPage />} />
          <Route path="benchmarks" element={<BenchmarksPage />} />
          <Route path="discovery" element={<DiscoveryPage />} />
          <Route path="patterns" element={<PatternsPage />} />
          <Route path="privacy" element={<PrivacyPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="remote" element={<RemotePage />} />
          <Route path="terminals" element={<TerminalsPage />} />
          {/* D-6: an unknown route gets an honest page instead of a
              silent redirect that reads as a navigation bug. */}
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </motion.div>
    </AnimatePresence>
  );
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
  const routeHidden = isSectionHidden(gov.data, navIdForPath(pathname) ?? "");
  // Close the drawer whenever the route changes (nav tap, command
  // palette, back button) so it never lingers over the new page.
  useEffect(() => {
    setMobileNavOpen(false);
  }, [pathname]);
  // Once opened, keep the drawer mounted so subsequent ? presses
  // are instant. First open pays the chunk-fetch cost.
  const [helpEverOpened, setHelpEverOpened] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  useEffect(() => {
    if (helpOpen && !helpEverOpened) setHelpEverOpened(true);
  }, [helpOpen, helpEverOpened]);

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
          <main className="flex min-w-0 flex-1 flex-col">
            <TopBar onHelp={openHelp} onMenu={() => setMobileNavOpen(true)} />
            <RestartPendingBanner />
            <IntegrityBanner />
            <ManagedBanner gov={gov.data} />
            <DemoBanner />
            <AnnouncementBanner />
            {/* Enterprise update management (W5): what the ORG has said about
                this node's version, as opposed to the npm pill in the TopBar
                which asks the public registry on a click. One loopback GET on
                mount, no polling. */}
            <UpdateBanner />
            <BudgetBanner />
            <FirstCaptureToast />
            <ToastViewport />
            <KonamiEgg />
            <FilterBar onOpenPalette={() => setPaletteOpen(true)} />
            <div className="min-h-0 flex-1 overflow-y-auto">
              {routeHidden ? (
                <ManagedNotice gov={gov.data} />
              ) : (
                /* D-6: the boundary sits below the shell so a crashing
                   page can't take the sidebar/topbar with it; keying on
                   pathname resets it when the user navigates away. */
                <RouteErrorBoundary>
                  <Suspense fallback={<RouteFallback />}>
                    <AnimatedRoutes />
                  </Suspense>
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
          <CommandPalette
            open={paletteOpen}
            onClose={() => setPaletteOpen(false)}
          />
        </div>
      </FilterProvider>
    </TourProvider>
    </HelpSlotProvider>
  );
}
