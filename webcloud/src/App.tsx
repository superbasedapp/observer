import type { ReactNode } from "react";
import { Suspense, lazy, useEffect, useState } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { PageTransition, TopProgress } from "@shared/primitives/Motion";
import { Skeleton } from "@shared/primitives/Skeleton";
import { usePortalActivity } from "./lib/query";
import { useRouteRider } from "@shared/lib/routeRider";
import { DashboardSkeleton } from "./components/LoadState";
import { getPersonalPlane, getSecondFactor, getSession, hasCsrf, onCsrfSync } from "./api";
import { clearConsentState, loadConsent, needsConsentSetup } from "./consent";
import { Sidebar } from "./components/Sidebar";
import { TopBar } from "./components/TopBar";
import { SignIn } from "./pages/SignIn";
import { ConsentSetup } from "./pages/ConsentSetup";
import { SecondFactor } from "./pages/SecondFactor";
import { legacyView } from "./lib/personalModel";
import { CONNECT_CODE_KEY, routerPath, safeReturnTo } from "./lib/connectModel";
import { SIGN_UP_ROUTE } from "./lib/signInModel";
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
const Home = lazy(() =>
  import("./pages/Home").then((m) => ({ default: m.Home })),
);
const ConnectApprove = lazy(() =>
  import("./pages/ConnectApprove").then((m) => ({ default: m.ConnectApprove })),
);
const ConnectEntry = lazy(() =>
  import("./pages/ConnectEntry").then((m) => ({ default: m.ConnectEntry })),
);
const CreateTeam = lazy(() =>
  import("./pages/CreateTeam").then((m) => ({ default: m.CreateTeam })),
);
const OrgDetail = lazy(() =>
  import("./pages/OrgDetail").then((m) => ({ default: m.OrgDetail })),
);
const Security = lazy(() =>
  import("./pages/Security").then((m) => ({ default: m.Security })),
);
const Moved = lazy(() =>
  import("./pages/Moved").then((m) => ({ default: m.Moved })),
);
import { PortalFooter } from "./components/PortalFooter";

// RequireAuth guards a page: "signed in" is purely whether the CSRF token is
// still in memory. By the time routes render, App has already resolved the
// boot-time getSession() call AND the consent load, so this correctly
// reflects a live cookie — not just what happened to survive a reload in
// memory. D-IND-8: the personal-plane consent screen no longer gates the
// console (an individual is an org of one; its sharing is the machine's own
// choice); it stays reachable at /consent from the Privacy page.
//
// The authenticated app shell (left sidebar + top status bar, matching the
// local dashboard) lives here: only routes that pass the gate get it. The
// sign-in / consent-setup screens above render full-screen, with no shell.
function RequireAuth({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();
  if (!hasCsrf()) {
    return <Navigate to={signInPath(pathname)} replace />;
  }
  return <Shell>{children}</Shell>;
}

/** signInPath is sign-in with return_to set back to the router path the
 * visitor asked for, so the sign-in lands them there (Getting started v2:
 * an approve link opened while signed out comes back to its machine). */
function signInPath(pathname: string): string {
  const back = safeReturnTo("/portal" + pathname);
  return back ? "/?return_to=" + encodeURIComponent(back) : "/";
}

// ConnectGate guards the two connect pages (the approve and verify URLs):
// they render full-screen, without the shell, and a signed-out visitor goes
// to sign-in and comes back.
function ConnectGate({ children }: { children: ReactNode }) {
  const { pathname, search } = useLocation();
  if (!hasCsrf()) {
    const code = new URLSearchParams(search).get("code");
    if (code) {
      try {
        sessionStorage.setItem(CONNECT_CODE_KEY, code);
      } catch {
        // Storage unavailable: the code is typed again after sign-in.
      }
    }
    return <Navigate to={signInPath(pathname)} replace />;
  }
  return <Suspense fallback={<BootSkeleton />}>{children}</Suspense>;
}

// Legacy wraps an old personal portal page (Overview, Sessions,
// SessionDetail, Community, Usage). They are out of the navigation; while the
// personal plane is serving they still render (their data stays reachable
// until it has moved to the personal org), and once it is retired they render
// the moved notice instead (lib/personalModel.ts LEGACY_RULES).
function Legacy({ children }: { children: ReactNode }) {
  return legacyView(getPersonalPlane()).routes === "moved" ? <Moved /> : <>{children}</>;
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

// RootRoute picks the landing page for "/": sign-in when signed out,
// otherwise the page a sign-in was asked to return to, else Home (Getting
// started v2: machines, the personal dashboard, then teams).
function RootRoute() {
  const { search } = useLocation();
  if (!hasCsrf()) {
    return <SignIn />;
  }
  const back = safeReturnTo(new URLSearchParams(search).get("return_to"));
  return <Navigate to={back ? routerPath(back) : "/home"} replace />;
}

// SignUpRoute is "/sign-up", the create-an-account entry the marketing
// site's "Get started" links to (hosted sign-in fix, lane A): signed out it
// is the sign-up variant of the sign-in page, which leaves for the
// provider's sign-up screen by itself; signed in there is nothing to create,
// so it goes where a sign-in would (the return_to, else Home).
function SignUpRoute() {
  const { search } = useLocation();
  if (!hasCsrf()) {
    return <SignIn variant="sign-up" />;
  }
  const back = safeReturnTo(new URLSearchParams(search).get("return_to"));
  return <Navigate to={back ? routerPath(back) : "/home"} replace />;
}

// ConsentRoute guards "/consent" itself: signed out bounces to sign-in, and
// an account whose choices are already stored goes back to the console
// (revisiting the choice lives on the Privacy page, not here). Nothing sends
// an account here any more; the Privacy page links to it (D-IND-8).
function ConsentRoute() {
  if (!hasCsrf()) {
    return <Navigate to="/" replace />;
  }
  if (!needsConsentSetup()) {
    return <Navigate to="/home" replace />;
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
    "checking" | "signed-out" | "signed-in" | "second-factor"
  >("checking");

  useEffect(() => {
    let live = true;
    getSession()
      .then(async (s) => {
        // The consent state is loaded BEFORE the first routed render, for the
        // same reason the session is: the route decision reads it, so deciding
        // before it is known would flash the wrong page (or, worse, skip the
        // consent screen for an account that has never seen it).
        // C2: a session whose passkey step is pending can reach nothing but
        // that step (the server refuses the rest), so the consent load and
        // every route wait behind it.
        if (s && getSecondFactor()?.pending) {
          if (live) setSession("second-factor");
          return;
        }
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
  if (session === "second-factor") {
    return <SecondFactor />;
  }

  return (
    <Routes>
      <Route path="/" element={<RootRoute />} />
      <Route path={SIGN_UP_ROUTE} element={<SignUpRoute />} />
      <Route path="/consent" element={<ConsentRoute />} />
      {/* C2: the team sign-in sends a member here when it needs a passkey. */}
      <Route path="/second-factor" element={hasCsrf() ? <SecondFactor /> : <Navigate to="/" replace />} />
      <Route
        path="/overview"
        element={
          <RequireAuth>
            <Legacy>
              <Overview />
            </Legacy>
          </RequireAuth>
        }
      />
      <Route
        path="/home"
        element={
          <RequireAuth>
            <Home />
          </RequireAuth>
        }
      />
      {/* Organizations became Home (Getting started v2); old links land there. */}
      <Route path="/orgs" element={<Navigate to="/home" replace />} />
      <Route
        path="/connect"
        element={
          <ConnectGate>
            <ConnectEntry />
          </ConnectGate>
        }
      />
      <Route
        path="/connect/:id"
        element={
          <ConnectGate>
            <ConnectApprove />
          </ConnectGate>
        }
      />
      <Route
        path="/orgs/new"
        element={
          <RequireAuth>
            <CreateTeam />
          </RequireAuth>
        }
      />
      <Route
        path="/orgs/:id"
        element={
          <RequireAuth>
            <OrgDetail />
          </RequireAuth>
        }
      />
      <Route
        path="/sessions"
        element={
          <RequireAuth>
            <Legacy>
              <Sessions />
            </Legacy>
          </RequireAuth>
        }
      />
      <Route
        path="/sessions/:id"
        element={
          <RequireAuth>
            <Legacy>
              <SessionDetail />
            </Legacy>
          </RequireAuth>
        }
      />
      <Route
        path="/community"
        element={
          <RequireAuth>
            <Legacy>
              <Community />
            </Legacy>
          </RequireAuth>
        }
      />
      <Route
        path="/usage"
        element={
          <RequireAuth>
            <Legacy>
              <Usage />
            </Legacy>
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
      <Route
        path="/security"
        element={
          <RequireAuth>
            <Security />
          </RequireAuth>
        }
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

// Leaf reader of the query cache's foreground activity. Keep it a leaf: the
// shell re-rendering on every busy/idle flip would re-render the whole app.
// D-665..D-669: Obs rides the line only during a slow ROUTE load (useRouteRider:
// from navigation until that page's own requests settle), never for a later
// filter change, refetch or poll.
function ActivityProgress() {
  const { pathname } = useLocation();
  const active = usePortalActivity() > 0;
  const rider = useRouteRider(pathname, active);
  return <TopProgress active={active} rider={rider} className="z-40" />;
}
