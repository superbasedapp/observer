import type { ReactNode } from "react";
import { useEffect, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { getSession, hasCsrf, onCsrfSync } from "./api";
import { clearConsentState, loadConsent, needsConsentSetup } from "./consent";
import { Sidebar } from "./components/Sidebar";
import { TopBar } from "./components/TopBar";
import { SignIn } from "./pages/SignIn";
import { ConsentSetup } from "./pages/ConsentSetup";
import { Overview } from "./pages/Overview";
import { Sessions } from "./pages/Sessions";
import { SessionDetail } from "./pages/SessionDetail";
import { Community } from "./pages/Community";
import { Usage } from "./pages/Usage";
import { Billing } from "./pages/Billing";
import { Privacy } from "./pages/Privacy";
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
  return (
    <div className="app-shell">
      <Sidebar />
      <div className="app-shell-main">
        <TopBar />
        <main className="main">{children}</main>
        <PortalFooter />
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
    return <div className="boot-loading">Loading...</div>;
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
