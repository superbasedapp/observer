// The staff console's session state: who is signed in (GET /staff/api/me),
// what the server offers (GET /staff/api/features), and the passkey
// re-verification every change needs. One owner (StaffSessionProvider);
// pages read it through useStaff.

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { createQueryCache } from "@shared/lib/queryCache";
import { useQuery } from "@shared/lib/useQuery";
import { getFeatures, getMe, hasStaffCsrf, signInWithPasskey, signOut as apiSignOut, type StaffFeatures, type StaffMe } from "./api";
import { can, freshness, type Freshness } from "./lib/model";

/** staffCache is the staff console's single query cache (separate from the
 *  portal's: the two apps never share a page load). */
export const staffCache = createQueryCache();

export type StaffQuery<T> = {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
};

/** useStaffQuery reads key through fetcher via the staff cache. */
export function useStaffQuery<T>(key: string | null, fetcher: () => Promise<T>, deps: readonly unknown[] = []): StaffQuery<T> {
  const run = useCallback(() => fetcher(), [fetcher]); // eslint-disable-line react-hooks/exhaustive-deps
  const q = useQuery<T, T>(staffCache, key, run, deps, { keepPrevious: false });
  const raw = q.error;
  const error = raw != null && !(q.loading || q.isRefreshing) ? (raw instanceof Error ? raw.message : String(raw)) : null;
  return { data: q.data, error, loading: q.loading, reload: q.reload };
}

/** invalidateStaff refetches a key after a change. */
export function invalidateStaff(key: string): void {
  staffCache.invalidate(key);
}

export interface StaffSession {
  me: StaffMe;
  features: StaffFeatures;
  /** feature reports whether an optional screen's route is mounted. */
  feature: (name: string) => boolean;
  /** may reports whether this role can ever perform a staff action. */
  may: (action: string) => boolean;
  /** fresh is the live countdown of the last passkey assertion. */
  fresh: Freshness;
  /** ready reports whether a change can be sent without a passkey prompt. */
  ready: boolean;
  /** reverify runs a passkey assertion (a fresh window and a CSRF token). */
  reverify: () => Promise<void>;
  signOut: () => Promise<void>;
}

const Ctx = createContext<StaffSession | null>(null);

/** useStaff is the signed-in session. Only pages under the provider call it. */
export function useStaff(): StaffSession {
  const s = useContext(Ctx);
  if (!s) throw new Error("useStaff outside StaffSessionProvider");
  return s;
}

/** useNow ticks every second while mounted (the freshness countdown). */
function useNow(): Date {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return now;
}

export function StaffSessionProvider({
  me,
  features,
  onChange,
  onSignedOut,
  children,
}: {
  me: StaffMe;
  features: StaffFeatures;
  /** onChange re-reads me and features (after a re-verification). */
  onChange: () => Promise<void>;
  onSignedOut: () => void;
  children: ReactNode;
}) {
  const now = useNow();
  const reverify = useCallback(async () => {
    await signInWithPasskey(navigator.credentials);
    await onChange();
  }, [onChange]);
  const signOut = useCallback(async () => {
    try {
      await apiSignOut();
    } finally {
      // The caller reloads the page, which drops every cached read.
      onSignedOut();
    }
  }, [onSignedOut]);
  const fresh = freshness(me.fresh_until, now);
  const value = useMemo<StaffSession>(
    () => ({
      me,
      features,
      feature: (n) => !!features.features[n],
      may: (a) => can(features.capabilities, a),
      fresh,
      ready: fresh.fresh && hasStaffCsrf(),
      reverify,
      signOut,
    }),
    // fresh changes every second; the rest only on a re-read.
    [me, features, fresh.label, fresh.fresh, reverify, signOut], // eslint-disable-line react-hooks/exhaustive-deps
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

/** StaffSessionForTest provides a fixed session (render tests only). */
export function StaffSessionForTest({ value, children }: { value: StaffSession; children: ReactNode }) {
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export { getFeatures, getMe };
