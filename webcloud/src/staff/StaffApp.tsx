// The staff console app (managed-SaaS M6.8; served by `observer-cloud staff
// serve` on the staff host under /staff/, never by the customer portal). Boot
// reads GET /staff/api/me: a 401 shows the passkey sign-in, anything else the
// console. Optional screens appear only when GET /staff/api/features says
// their route is mounted (a coordinating lane lights one up by adding it).

import { Suspense, lazy, useCallback, useEffect, useState, type ReactNode } from "react";
import { NavLink, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { Building2, Gauge, KeyRound, ListChecks, LogOut, ScrollText, ShieldCheck, Trash2, type LucideIcon } from "lucide-react";
import { Button } from "@shared/primitives/Button";
import { Icon } from "@shared/primitives/Icon";
import { Pill } from "@shared/primitives/Pill";
import { Skeleton } from "@shared/primitives/Skeleton";
import { ErrorState } from "@shared/primitives/ErrorState";
import { PageTransition } from "@shared/primitives/Motion";
import { BrandLockup } from "../components/BrandMark";
import { ThemeToggle } from "../components/ThemeToggle";
import { StaffApiError, getFeatures, getMe, type StaffFeatures, type StaffMe } from "./api";
import { StaffSessionProvider, useStaff } from "./session";
import { StaffSignIn } from "./pages/SignIn";
import { passkeyErrorText } from "./lib/webauthn";

const Orgs = lazy(() => import("./pages/Orgs").then((m) => ({ default: m.Orgs })));
const OrgDetail = lazy(() => import("./pages/OrgDetail").then((m) => ({ default: m.OrgDetail })));
const Availability = lazy(() => import("./pages/Availability").then((m) => ({ default: m.Availability })));
const Support = lazy(() => import("./pages/Support").then((m) => ({ default: m.Support })));
const AuditLog = lazy(() => import("./pages/AuditLog").then((m) => ({ default: m.AuditLog })));
const Optional = lazy(() => import("./pages/Optional").then((m) => ({ default: m.OptionalScreen })));
const TeamAllowlist = lazy(() => import("./pages/TeamAllowlist").then((m) => ({ default: m.TeamAllowlist })));

interface StaffNavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  /** feature gates the item on GET /staff/api/features (none: always). */
  feature?: string;
}

/** STAFF_NAV is the console's route table. */
export const STAFF_NAV: StaffNavItem[] = [
  { to: "/orgs", label: "Orgs", icon: Building2, feature: "orgs" },
  { to: "/availability", label: "Availability", icon: Gauge },
  { to: "/support", label: "Support access", icon: ShieldCheck },
  { to: "/log", label: "Audit log", icon: ScrollText },
  { to: "/team-allowlist", label: "Team allow-list", icon: ListChecks, feature: "team_allowlist" },
  { to: "/deletions", label: "Deletions", icon: Trash2, feature: "deletion_queue" },
];

type Boot = { kind: "loading" } | { kind: "signed-out" } | { kind: "error"; message: string } | { kind: "ready"; me: StaffMe; features: StaffFeatures };

export function StaffApp() {
  const [boot, setBoot] = useState<Boot>({ kind: "loading" });
  const load = useCallback(async () => {
    try {
      const [me, features] = await Promise.all([getMe(), getFeatures()]);
      setBoot({ kind: "ready", me, features });
    } catch (e) {
      if (e instanceof StaffApiError && e.status === 401) setBoot({ kind: "signed-out" });
      else setBoot({ kind: "error", message: e instanceof Error ? e.message : String(e) });
    }
  }, []);
  useEffect(() => {
    void load();
  }, [load]);

  switch (boot.kind) {
    case "loading":
      return <BootFrame />;
    case "signed-out":
      return <StaffSignIn onSignedIn={load} />;
    case "error":
      return (
        <div className="p-8">
          <ErrorState variant="page" title="The staff console could not load" error={boot.message} onRetry={() => void load()} />
        </div>
      );
    case "ready":
      return (
        <StaffSessionProvider me={boot.me} features={boot.features} onChange={load} onSignedOut={() => window.location.assign("/staff/")}>
          <StaffShell>
            <Routes>
              <Route path="/" element={<Navigate to={boot.features.features.orgs ? "/orgs" : "/availability"} replace />} />
              <Route path="/orgs" element={<Orgs />} />
              <Route path="/orgs/:id" element={<OrgDetail />} />
              <Route path="/availability" element={<Availability />} />
              <Route path="/support" element={<Support />} />
              <Route path="/log" element={<AuditLog />} />
              <Route path="/team-allowlist" element={<TeamAllowlist />} />
              <Route path="/deletions" element={<Optional feature="deletion_queue" title="Deletions" path="/api/deletions" />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </StaffShell>
        </StaffSessionProvider>
      );
  }
}

function BootFrame() {
  return (
    <div className="app-shell" aria-busy="true">
      <div className="sidebar" aria-hidden>
        <div className="sidebar-brand">
          <Skeleton className="h-4 w-24" />
        </div>
      </div>
      <div className="app-shell-main">
        <main className="main">
          <div className="main-inner">
            <Skeleton className="h-8 w-64" />
          </div>
        </main>
      </div>
    </div>
  );
}

function StaffShell({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();
  const staff = useStaff();
  const items = STAFF_NAV.filter((i) => !i.feature || staff.feature(i.feature));
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <BrandLockup size={21} />
        </div>
        <nav className="sidebar-nav" aria-label="Staff console">
          {items.map((item) => (
            <NavLink key={item.to} to={item.to} className={({ isActive }) => (isActive ? "nav-item nav-item-active" : "nav-item")}>
              <span className="nav-item-icon" aria-hidden="true">
                <Icon icon={item.icon} size="md" />
              </span>
              <span className="nav-item-label">{item.label}</span>
            </NavLink>
          ))}
        </nav>
      </aside>
      <div className="app-shell-main">
        <StaffTopBar />
        <main className="main">
          <PageTransition routeKey={pathname} className="main-inner">
            <Suspense fallback={<Skeleton className="h-8 w-64" />}>{children}</Suspense>
          </PageTransition>
        </main>
      </div>
    </div>
  );
}

function StaffTopBar() {
  const staff = useStaff();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  async function verify() {
    setBusy(true);
    setErr(null);
    try {
      await staff.reverify();
    } catch (e) {
      setErr(passkeyErrorText(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <header className="topbar">
      <div className="topbar-brand">
        <BrandLockup size={17} />
        <span className="ml-2 hidden sm:inline-flex">
          <Pill variant="danger" case="upper">
            staff
          </Pill>
        </span>
      </div>
      <div className="topbar-actions">
        <span className="hidden text-[11.5px] text-fg-3 md:inline" role="status" aria-live="polite" title={err ?? undefined}>
          {err ?? (staff.ready ? staff.fresh.label : "Verify your passkey to make changes")}
        </span>
        {!staff.ready && (
          <Button size="sm" variant="soft" iconLeft={KeyRound} onClick={() => void verify()} loading={busy}>
            Verify passkey
          </Button>
        )}
        <span className="topbar-account hidden sm:inline">{staff.me.display_name}</span>
        <Pill variant={staff.me.role === "support" ? "neutral" : "accent"}>{staff.me.role}</Pill>
        <span className="hidden sm:inline-flex">
          <ThemeToggle />
        </span>
        <Button size="sm" variant="ghost" iconLeft={LogOut} onClick={() => void staff.signOut()}>
          Sign out
        </Button>
      </div>
    </header>
  );
}
