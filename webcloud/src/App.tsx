import type { ReactNode } from "react";
import { Suspense, lazy, useEffect, useState } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { PageTransition, TopProgress } from "@shared/primitives/Motion";
import { Skeleton } from "@shared/primitives/Skeleton";
import { usePortalActivity } from "./lib/query";
import { DashboardSkeleton } from "./components/LoadState";
import { getSession, hasCsrf, onCsrfSync } from "./api";
import { clearConsentState, loadConsent, needsConsentSetup } from "./consent";
import { Sidebar } from "./components/Sidebar";
import { TopBar } from "./components/TopBar";
import { SignIn } from "./pages/SignIn";
import { ConsentSetup } from "./pages/ConsentSetup";
// Signed-in pages load per route: a signed-out visitor (SignIn, eager above)
// never downloads recharts or the dashboard pages, and each page's chunk is
// fetched in parallel with its data. The shell shows a page-shaped skeleton
// meanwhile (Suspense sits inside the page transition).
const Overview = lazy(() =>
  import("./pages/Overview").then((m) => ({ default: m.Overview })),
);
const Sessions = lazy(() =>
  import("./pages/Sessions").then((m) => ({ default: m.Sessions })),
);
const SessionDetail = lazy(() =>
  import("./pages/SessionDetail").then((m) => ({ default: m.SessionDetail })),
);
const Community = lazy(() =>
  import("./pages/Community").then((m) => ({ default: m.Community })),
);
const Usage = lazy(() =>
  import("./pages/Usage").then((m) => ({ default: m.Usage })),
);
const Billing = lazy(() =>
  import("./pages/Billing").then((m) => ({ default: m.Billing })),
);
const Privacy = lazy(() =>
  import("./pages/Privacy").then((m) => ({ default: m.Privacy })),
);
import { PortalFooter } from "./components/PortalFooter";

// RequireAuth guards a page: "signed in" is purely whether the CSRF token is
// still in memory. By the time routes render, App has already resolved the
// boot-time getSession() call AND the consent load, so this correctly
// reflects a live cookie and real server-side consent state — not just what
// happened to survive a reload in memory. A signed-in account whose server
// state says the consent screen has never run is sent there first.
//
// The authenticated app shell (left sidebar + top status bar, matching the
// local dashboard) lives here: only routes that pass both gates get it. The
// sign-in / consent-setup screens above render full-screen, with no shell.
function RequireAuth({ children }: { children: ReactNode }) {
  if (!hasCsrf()) {
    return <Navigate to="/" replace />;
  }
  if (needsConsentSetup()) {
    return <Navigate to="/consent" replace />;
  }
  return <Shell>{children}</Shell>;
}

// Shell is the authenticated frame. The viewport-bounded .app-shell keeps
// the sidebar in place while .main scrolls on its own; the routed page
// enters with the shared page transition (keyed on the path, no exit
// phase), and the top progress bar shows while a foreground request runs
// (a page's first load, a filter change) - never for a background refetch.
function Shell({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();
  return (
    <div className="app-shell">
      <Sidebar />
      <div className="app-shell-main">
        <ActivityProgress />
        <TopBar />
        <main className="main">
          <PageTransition routeKey={pathname} className="main-inner">
            <Suspense fallback={<DashboardSkeleton />}>{children}</Suspense>
          </PageTransition>
        </main>
        <PortalFooter />
      </div>
    </div>
  );
}

// BootSkeleton stands in for the whole shell while the boot-time session and
// consent reads run, so the first paint is already the app's shape instead of
// a bare "Loading..." line followed by a layout jump.
function BootSkeleton() {
  return (
    <div className="app-shell" aria-busy="true">
      <div className="sidebar boot-sidebar" aria-hidden>
        <div className="sidebar-brand">
          <Skeleton className="h-4 w-24" />
        </div>
        <div className="sidebar-nav">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="my-1 h-5 w-full" />
          ))}
        </div>
      </div>
      <div className="app-shell-main">
        <div className="topbar" aria-hidden>
          <span />
          <Skeleton className="h-6 w-40" />
        </div>
        <main className="main">
          <div className="main-inner">
            <DashboardSkeleton />
          </div>
        </main>
      </div>
    </div>
  );
}

// RootRoute picks the landing page for "/": sign-in when signed out, the
// consent shell for a signed-in account that has never seen it, otherwise
// the app itself.
function RootRoute() {
  if (!hasCsrf()) {
    return <SignIn />;
  }
  if (needsConsentSetup()) {
    return <Navigate to="/consent" replace />;
  }
  return <Navigate to="/overview" replace />;
}

// ConsentRoute guards "/consent" itself: signed out bounces to sign-in, and
// an account whose choices are already stored skips straight past it
// (revisiting the choice lives on the Privacy page, not here).
function ConsentRoute() {
  if (!hasCsrf()) {
    return <Navigate to="/" replace />;
  }
  if (!needsConsentSetup()) {
    return <Navigate to="/overview" replace />;
  }
  return <ConsentSetup />;
}

export function App() {
  // "checking" gates the very first render on the boot-time getSession()
  // call — this is the reload-bounce fix (E8): we must not decide SignIn vs
  // app until we know whether the session cookie is still live and, if so,
  // have adopted the freshly rotated CSRF token it returns. Once resolved,
  // `session` also acts as the re-render trigger the routes below need: the
  // hasCsrf()/hasConsentAck() calls inside the Route elements always read
  // live module state, but React only re-evaluates them when something
  // triggers a re-render, which is what changing this state does.
  const [session, setSession] = useState<
    "checking" | "signed-out" | "signed-in"
  >("checking");

  useEffect(() => {
    let live = true;
    getSession()
      .then(async (s) => {
        // The consent state is loaded BEFORE the first routed render, for the
        // same reason the session is: the route decision reads it, so deciding
        // before it is known would flash the wrong page (or, worse, skip the
        // consent screen for an account that has never seen it).
        if (s) {
          await loadConsent();
        }
        if (live) setSession(s ? "signed-in" : "signed-out");
      })
      .catch(() => {
        if (live) setSession("signed-out");
      });
    return () => {
      live = false;
    };
  }, []);

  // Multi-tab CSRF sync: another tab that successfully calls
  // getSession()/login() (or signs out) broadcasts its already-rotated token
  // (or a sign-out) over BroadcastChannel; api.ts's onCsrfSync listener
  // adopts it into this tab's module state with NO network call and just
  // tells us to re-render so the routes below reflect it.
  useEffect(() => {
    return onCsrfSync((signedIn) => {
      if (!signedIn) {
        clearConsentState();
        setSession("signed-out");
        return;
      }
      // A sign-in adopted from another tab still needs this tab's own consent
      // state — the broadcast carries the token, not the account's server
      // state — so load it before flipping to signed-in.
      loadConsent().finally(() => setSession("signed-in"));
    });
  }, []);

  if (session === "checking") {
    return <BootSkeleton />;
  }

  return (
    <Routes>
      <Route path="/" element={<RootRoute />} />
      <Route path="/consent" element={<ConsentRoute />} />
      <Route
        path="/overview"
        element={
          <RequireAuth>
            <Overview />
          </RequireAuth>
        }
      />
      <Route
        path="/sessions"
        element={
          <RequireAuth>
            <Sessions />
          </RequireAuth>
        }
      />
      <Route
        path="/sessions/:id"
        element={
          <RequireAuth>
            <SessionDetail />
          </RequireAuth>
        }
      />
      <Route
        path="/community"
        element={
          <RequireAuth>
            <Community />
          </RequireAuth>
        }
      />
      <Route
        path="/usage"
        element={
          <RequireAuth>
            <Usage />
          </RequireAuth>
        }
      />
      <Route
        path="/billing"
        element={
          <RequireAuth>
            <Billing />
          </RequireAuth>
        }
      />
      <Route
        path="/privacy"
        element={
          <RequireAuth>
            <Privacy />
          </RequireAuth>
        }
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

// Leaf reader of the query cache's foreground activity. Keep it a leaf: the
// shell re-rendering on every busy/idle flip would re-render the whole app.
function ActivityProgress() {
  return <TopProgress active={usePortalActivity() > 0} className="z-40" />;
}
